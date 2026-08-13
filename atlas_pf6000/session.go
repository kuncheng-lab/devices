package atlas_pf6000

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const commandMaxAttempts = 3

var errCommandTimeout = errors.New("PF6000 命令确认超时")

type commandReply struct {
	Accepted bool
	MID      string
	Code     string
}

type commandWaiter struct {
	conn net.Conn
	ch   chan commandReply
}

func (c *Client) resetProtocolStateLocked() {
	if c.psetChanged != nil {
		close(c.psetChanged)
	}
	c.commandWaiters = make(map[string][]*commandWaiter)
	c.psetSelectionSubscribed = false
	c.selectedPset = ""
	c.psetChanged = make(chan struct{})
	c.resultSubscribed = false
	c.multiSpindleResultSubscribed = false
	c.multiSpindleResultSubscribePending = false
	c.resultSubscribePending = false
}

func (c *Client) dispatchCommandReply(conn net.Conn, msg OpenProtocolMessage) {
	if msg.MID != "0004" && msg.MID != "0005" {
		return
	}
	requestedMID := FieldOrUnknown(msg.Data, 0, 4)
	reply := commandReply{
		Accepted: msg.MID == "0005",
		MID:      requestedMID,
	}
	if !reply.Accepted {
		reply.Code = FieldOrUnknown(msg.Data, 4, 6)
	}

	var waiter *commandWaiter
	c.mu.Lock()
	if c.conn == conn {
		waiters := c.commandWaiters[requestedMID]
		if len(waiters) > 0 {
			waiter = waiters[0]
			if len(waiters) == 1 {
				delete(c.commandWaiters, requestedMID)
			} else {
				c.commandWaiters[requestedMID] = waiters[1:]
			}
		}
	}
	c.mu.Unlock()
	if waiter != nil {
		waiter.ch <- reply
	}
}

func (c *Client) sendCommandOnce(ctx context.Context, conn net.Conn, req OpenProtocolProbeRequest, timeout time.Duration) (commandReply, error) {
	if err := ctx.Err(); err != nil {
		return commandReply{}, err
	}
	requestedMID := fmt.Sprintf("%04d", req.MID)
	waiter := &commandWaiter{conn: conn, ch: make(chan commandReply, 1)}

	c.mu.Lock()
	if c.conn != conn || c.done == nil {
		c.mu.Unlock()
		return commandReply{}, fmt.Errorf("PF6000 连接已断开")
	}
	done := c.done
	c.commandWaiters[requestedMID] = append(c.commandWaiters[requestedMID], waiter)
	c.mu.Unlock()

	if err := c.sendPF6000Request(conn, req); err != nil {
		c.removeCommandWaiter(requestedMID, waiter)
		return commandReply{}, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case reply := <-waiter.ch:
		return reply, nil
	case <-ctx.Done():
		c.removeCommandWaiter(requestedMID, waiter)
		return commandReply{}, ctx.Err()
	case <-done:
		c.removeCommandWaiter(requestedMID, waiter)
		return commandReply{}, fmt.Errorf("PF6000 在等待 MID %s 确认时断开", requestedMID)
	case <-timer.C:
		c.removeCommandWaiter(requestedMID, waiter)
		return commandReply{}, fmt.Errorf("%w: MID %s", errCommandTimeout, requestedMID)
	}
}

func (c *Client) removeCommandWaiter(mid string, target *commandWaiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	waiters := c.commandWaiters[mid]
	for i, waiter := range waiters {
		if waiter != target {
			continue
		}
		waiters = append(waiters[:i], waiters[i+1:]...)
		if len(waiters) == 0 {
			delete(c.commandWaiters, mid)
		} else {
			c.commandWaiters[mid] = waiters
		}
		return
	}
}

func (c *Client) sendCommandWithRetry(ctx context.Context, conn net.Conn, req OpenProtocolProbeRequest, timeout time.Duration) (commandReply, error) {
	if timeout <= 0 {
		timeout = time.Duration(DefaultTimeoutMs) * time.Millisecond
	}
	var lastErr error
	for attempt := 1; attempt <= commandMaxAttempts; attempt++ {
		reply, err := c.sendCommandOnce(ctx, conn, req, timeout)
		if err == nil {
			return reply, nil
		}
		lastErr = err
		if !errors.Is(err, errCommandTimeout) {
			return commandReply{}, err
		}
		c.log("PF6000 MID %04d 第 %d/%d 次等待确认超时", req.MID, attempt, commandMaxAttempts)
	}
	err := fmt.Errorf("PF6000 MID %04d 连续 %d 次未收到确认，按协议断开当前会话: %w", req.MID, commandMaxAttempts, lastErr)
	c.Disconnect()
	return commandReply{}, err
}

func rejectedCommandError(reply commandReply) error {
	return fmt.Errorf("PF6000 MID %s 被拒绝，错误码 %s (%s)", reply.MID, reply.Code, OpenProtocolErrorText(reply.Code))
}

func (c *Client) sendAcceptedCommand(ctx context.Context, conn net.Conn, req OpenProtocolProbeRequest, timeout time.Duration) error {
	reply, err := c.sendCommandWithRetry(ctx, conn, req, timeout)
	if err != nil {
		return err
	}
	if !reply.Accepted {
		return rejectedCommandError(reply)
	}
	return nil
}

func (c *Client) EnsureSubscriptions(multiSpindle bool, timeout time.Duration) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	conn, err := c.connectedSession()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := c.ensurePsetSelectionSubscription(ctx, conn, timeout); err != nil {
		return err
	}
	return c.ensureResultSubscription(ctx, conn, multiSpindle, timeout)
}

func (c *Client) EnsureResultSubscription(multiSpindle bool, timeout time.Duration) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	conn, err := c.connectedSession()
	if err != nil {
		return err
	}
	return c.ensureResultSubscription(context.Background(), conn, multiSpindle, timeout)
}

func (c *Client) ensureResultSubscription(ctx context.Context, conn net.Conn, multiSpindle bool, timeout time.Duration) error {
	if c.ResultSubscriptionReady(multiSpindle) {
		return nil
	}

	mid := 60
	duplicateCode := "09"
	if multiSpindle {
		mid = 100
		duplicateCode = "33"
	}

	c.mu.Lock()
	if c.conn == conn {
		if multiSpindle {
			c.multiSpindleResultSubscribePending = true
		} else {
			c.resultSubscribePending = true
		}
	}
	c.mu.Unlock()

	reply, err := c.sendCommandWithRetry(ctx, conn, OpenProtocolProbeRequest{MID: mid, Revision: 1}, timeout)
	if err != nil {
		c.clearResultSubscriptionPending(conn, multiSpindle)
		return err
	}
	if !reply.Accepted && reply.Code != duplicateCode {
		c.clearResultSubscriptionPending(conn, multiSpindle)
		return rejectedCommandError(reply)
	}

	c.mu.Lock()
	if c.conn == conn {
		if multiSpindle {
			c.multiSpindleResultSubscribed = true
			c.multiSpindleResultSubscribePending = false
		} else {
			c.resultSubscribed = true
			c.resultSubscribePending = false
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *Client) clearResultSubscriptionPending(conn net.Conn, multiSpindle bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	if multiSpindle {
		c.multiSpindleResultSubscribePending = false
	} else {
		c.resultSubscribePending = false
	}
}

func (c *Client) ensurePsetSelectionSubscription(ctx context.Context, conn net.Conn, timeout time.Duration) error {
	c.mu.Lock()
	ready := c.conn == conn && c.psetSelectionSubscribed && c.selectedPset != ""
	c.mu.Unlock()
	if ready {
		return nil
	}

	reply, err := c.sendCommandWithRetry(ctx, conn, OpenProtocolProbeRequest{MID: 14, Revision: 1}, timeout)
	if err != nil {
		return err
	}
	if !reply.Accepted && reply.Code != "13" {
		return rejectedCommandError(reply)
	}

	c.mu.Lock()
	if c.conn == conn {
		c.psetSelectionSubscribed = true
	}
	c.mu.Unlock()
	if _, err := c.waitForSelectedPset(ctx, conn, "", timeout); err != nil {
		return fmt.Errorf("PF6000 已确认 MID 0014，但未返回当前 Pset: %w", err)
	}
	return nil
}

func (c *Client) ResultSubscriptionReady(multiSpindle bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return false
	}
	if multiSpindle {
		return c.multiSpindleResultSubscribed
	}
	return c.resultSubscribed
}

func (c *Client) SelectPsetForStationContext(ctx context.Context, psetID string, station int, timeout time.Duration) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	psetID = normalizePsetText(psetID)
	conn, err := c.connectedSession()
	if err != nil {
		return err
	}

	c.mu.Lock()
	psetSubscriptionReady := c.psetSelectionSubscribed && c.selectedPset != ""
	resultSubscriptionReady := c.resultSubscribed || c.multiSpindleResultSubscribed
	selectedBefore := c.selectedPset
	c.mu.Unlock()
	if !psetSubscriptionReady {
		return fmt.Errorf("PF6000 Pset 选择订阅尚未就绪")
	}
	if !resultSubscriptionReady {
		return fmt.Errorf("PF6000 拧紧结果订阅尚未就绪")
	}

	if selectedBefore == psetID {
		c.log("PF6000 Pset %s 已选中，无需重复选择", psetID)
		return nil
	}

	if err := c.sendAcceptedCommand(ctx, conn, OpenProtocolProbeRequest{
		MID:      18,
		Revision: 1,
		Station:  station,
		Data:     psetID,
	}, timeout); err != nil {
		return err
	}
	if _, err := c.waitForSelectedPset(ctx, conn, psetID, timeout); err != nil {
		return fmt.Errorf("PF6000 未确认选中 Pset %s: %w", psetID, err)
	}
	c.log("PF6000 已选择 Pset %s", psetID)
	return nil
}

func (c *Client) connectedSession() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || c.done == nil {
		return nil, fmt.Errorf("PF6000 未连接")
	}
	return c.conn, nil
}

func (c *Client) handleSelectedPset(conn net.Conn, psetID string) {
	psetID = normalizePsetText(psetID)
	c.mu.Lock()
	if c.conn != conn {
		c.mu.Unlock()
		return
	}
	c.selectedPset = psetID
	c.psetSelectionSubscribed = true
	close(c.psetChanged)
	c.psetChanged = make(chan struct{})
	c.mu.Unlock()
	c.log("PF6000 当前选中 Pset: %s", psetID)
}

func (c *Client) waitForSelectedPset(ctx context.Context, conn net.Conn, expected string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = time.Duration(DefaultTimeoutMs) * time.Millisecond
	}
	expected = strings.TrimSpace(expected)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		if c.conn != conn || c.done == nil {
			c.mu.Unlock()
			return "", fmt.Errorf("PF6000 连接已断开")
		}
		selected := c.selectedPset
		changed := c.psetChanged
		done := c.done
		c.mu.Unlock()

		if selected != "" && (expected == "" || selected == expected) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return selected, nil
		}
		select {
		case <-changed:
			continue
		case <-ctx.Done():
			return "", ctx.Err()
		case <-done:
			return "", fmt.Errorf("PF6000 连接已断开")
		case <-deadline.C:
			if expected == "" {
				return "", fmt.Errorf("等待 MID 0015 超时")
			}
			return "", fmt.Errorf("等待 MID 0015 返回 Pset %s 超时", expected)
		}
	}
}
