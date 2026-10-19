// Package event defines the security events the agent ships to the SOC backend.
package event

import "time"

const (
	SSHFailedLogin  = "SSH_FAILED_LOGIN"
	SSHInvalidUser  = "SSH_INVALID_USER"
	SSHLoginSuccess = "SSH_LOGIN_SUCCESS"
	SudoCommand     = "SUDO_COMMAND"
	SudoAuthFailure = "SUDO_AUTH_FAILURE"
	SudoDenied      = "SUDO_DENIED"
	PortOpened      = "PORT_OPENED"
	PortClosed      = "PORT_CLOSED"
	PortBaseline    = "PORT_BASELINE"
	AgentStarted    = "AGENT_STARTED"

	FileCreated       = "FILE_CREATED"
	FileModified      = "FILE_MODIFIED"
	FileDeleted       = "FILE_DELETED"
	FileBaseline      = "FILE_BASELINE"
	ProcessSuspicious = "PROCESS_SUSPICIOUS"
)

type Event struct {
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurredAt"`
	SourceIP   string         `json:"sourceIp,omitempty"`
	Username   string         `json:"username,omitempty"`
	Message    string         `json:"message,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`

	// Cursor is the journald cursor of the log line that produced the event.
	// It is persisted only after the event was delivered, so a restart resumes
	// exactly where delivery stopped.
	Cursor string `json:"-"`
}
