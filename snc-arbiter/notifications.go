// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/rand"
	"fmt"
	"time"
)

const notificationTTL = 24 * 60 * 60 // 24 hours in seconds

// NotificationEntry is one notification delivered to clients.
// Username is internal only (json:"-"): non-empty means it targets a specific user;
// empty means it is a broadcast notification for all users.
// CreatedBy is internal only (json:"-") and never sent to clients.
type NotificationEntry struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	CreatedAt int64  `json:"created_at"`
	CreatedBy string `json:"-"`
	Username  string `json:"-"`
}

func newNotificationID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return fmt.Sprintf("%x", b)
}

// addNotification inserts a broadcast notification (visible to all users).
func (d *DB) addNotification(id, message, createdBy string) error {
	_, err := d.db.Exec(
		`INSERT INTO notifications (id, message, created_by) VALUES (?, ?, ?)`,
		id, message, createdBy,
	)
	return err
}

// addUserNotification inserts a notification targeted at a specific user.
func (d *DB) addUserNotification(username, message string) error {
	id := newNotificationID()
	_, err := d.db.Exec(
		`INSERT INTO notifications (id, message, created_by, username) VALUES (?, ?, 'system', ?)`,
		id, message, username,
	)
	return err
}

// activeNotifications returns notifications created within the last 24 hours,
// newest first.  When username is non-empty, includes both broadcast entries
// (username IS NULL) and entries targeted at that specific user.
// When username is empty, returns only broadcast entries.
func (d *DB) activeNotifications(username string) ([]NotificationEntry, error) {
	cutoff := time.Now().Unix() - notificationTTL
	var rows interface {
		Next() bool
		Scan(...interface{}) error
		Close() error
		Err() error
	}
	var err error
	if username != "" {
		rows, err = d.db.Query(
			`SELECT id, message, created_at, created_by, COALESCE(username,'')
			 FROM notifications
			 WHERE created_at >= ? AND (username IS NULL OR username = ?)
			 ORDER BY created_at DESC`,
			cutoff, username,
		)
	} else {
		rows, err = d.db.Query(
			`SELECT id, message, created_at, created_by, COALESCE(username,'')
			 FROM notifications
			 WHERE created_at >= ? AND username IS NULL
			 ORDER BY created_at DESC`,
			cutoff,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationEntry
	for rows.Next() {
		var n NotificationEntry
		if err := rows.Scan(&n.ID, &n.Message, &n.CreatedAt, &n.CreatedBy, &n.Username); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// deleteNotification removes a notification by ID.
func (d *DB) deleteNotification(id string) error {
	_, err := d.db.Exec(`DELETE FROM notifications WHERE id = ?`, id)
	return err
}
