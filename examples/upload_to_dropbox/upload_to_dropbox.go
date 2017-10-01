package main

import (
	"fmt"
	"os"
	"time"

	"github.com/grokify/gotilla/fmt/fmtutil"
	dp "github.com/grokify/rclone-storage/dropbox"
	"github.com/grokify/rclone-storage/fs"
	"github.com/joho/godotenv"
)

type Info interface {
	// Name of the remote (as passed into NewFs)
	Name() string
	// Root of the remote (as passed into NewFs)
	Root() string
	// String returns a description of the FS
	String() string
	// Precision of the ModTimes in this Fs
	Precision() time.Duration
	// Returns the supported hash types of the filesystem
	Hashes() fs.HashSet
	// Features returns the optional features of this Fs
	Features() *fs.Features
}

type FileInfo struct {
	XName      string
	XRoot      string
	XPrecision time.Duration
	XHashes    fs.HashSet
	XFeatures  *fs.Features
}

func (fi FileInfo) Name() string {
	return fi.XName
}
func (fi FileInfo) String() string {
	return fi.XName
}
func (fi FileInfo) Root() string {
	return fi.XRoot
}
func (fi FileInfo) Precision() time.Duration {
	return fi.XPrecision
}
func (fi FileInfo) Hashes() fs.HashSet {
	return fi.XHashes
}
func (fi FileInfo) Features() *fs.Features {
	return fi.XFeatures
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	accessToken := os.Getenv("RCLONE_CONFIG_DROPBOX_ACCESS_TOKEN")

	remote := dp.NewFsToken("/", accessToken)
	fmtutil.PrintJSON(remote)
	res, err := remote.List("")
	if err != nil {
		panic(err)
	}
	for i, r := range res {
		fmt.Println(i)
		fmt.Printf("String: %v\n", r.String())
		fmt.Printf("Remote: %v\n", r.Remote())
	}
	fmt.Println(len(res))

	file, err := os.Open("./test_file.pdf")
	if err != nil {
		panic(err)
	}
	fi, err := file.Stat()
	if err != nil {
		// Could not obtain stat, handle error
		panic(err)
	}

	info := FileInfo{
		XName:      "RCS",
		XRoot:      "/",
		XPrecision: time.Millisecond,
		XHashes:    fs.NewHashSet(),
		XFeatures:  &fs.Features{},
	}

	oi := fs.NewStaticObjectInfo("test_file.pdf",
		time.Now(), fi.Size(), true, map[fs.HashType]string{}, info)

	fso, err := remote.Put(file, oi)
	if err != nil {
		panic(err)
	}
	fmtutil.PrintJSON(fso)

	time.Sleep(time.Second * 5)

	fmt.Println("DONE")
}
