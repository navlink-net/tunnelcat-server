// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build ios

package core

// On iOS, client updates go through the App Store review process.
// Self-updating binary replacement is not permitted. These stubs satisfy the
// interface so the shared tunnel logic compiles without change.

// Updater is a no-op on iOS.
type Updater struct {
	getControls func() []string
	OnReady     func(version string)
}

// NewUpdater returns a no-op updater for iOS.
func NewUpdater(getControls func() []string) *Updater {
	return &Updater{getControls: getControls}
}

// Start does nothing on iOS.
func (u *Updater) Start() {}

// ApplyPendingUpdate is a no-op on iOS.
func ApplyPendingUpdate() {}

// UpdateCleanup is a no-op on iOS.
func UpdateCleanup() {}
