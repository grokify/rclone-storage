package fs

import (
	"net"
	"time"
)

// Global
var (
	// Config is the global config
	Config = &ConfigInfo{
		LowLevelRetries: 3,
	}
)

// ConfigInfo is filesystem config options
type ConfigInfo struct {
	LogLevel       LogLevel
	StatsLogLevel  LogLevel
	DryRun         bool
	CheckSum       bool
	SizeOnly       bool
	IgnoreTimes    bool
	IgnoreExisting bool
	ModifyWindow   time.Duration
	Checkers       int
	Transfers      int
	ConnectTimeout time.Duration // Connect timeout
	Timeout        time.Duration // Data channel timeout
	DumpHeaders    bool
	DumpBodies     bool
	DumpAuth       bool
	//Filter             *Filter
	InsecureSkipVerify bool // Skip server certificate verification
	//DeleteMode         DeleteMode
	TrackRenames    bool // Track file renames.
	LowLevelRetries int
	UpdateOlder     bool // Skip files that are newer on the destination
	NoGzip          bool // Disable compression
	MaxDepth        int
	IgnoreSize      bool
	IgnoreChecksum  bool
	NoTraverse      bool
	NoUpdateModTime bool
	DataRateUnit    string
	BackupDir       string
	Suffix          string
	UseListR        bool
	//BufferSize         SizeSuffix
	TPSLimit        float64
	TPSLimitBurst   int
	BindAddr        net.IP
	DisableFeatures []string
	Immutable       bool
	//StreamingUploadCutoff SizeSuffix
}
