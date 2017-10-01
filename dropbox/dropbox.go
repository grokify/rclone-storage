package dropbox

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/dropbox/dropbox-sdk-go-unofficial/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/dropbox/files"
	"github.com/grokify/gotilla/time/timeutil"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/grokify/rclone-storage/fs"
	"github.com/grokify/rclone-storage/pacer"
)

// Constants
const (
	//minSleep      = 10 * time.Millisecond
	//maxSleep      = 2 * time.Second
	minSleep      = 1 * time.Millisecond
	maxSleep      = 2 * time.Millisecond
	decayConstant = 2 // bigger for slower decay, exponential
)

var (
	// A regexp matching path names for files Dropbox ignores
	// See https://www.dropbox.com/en/help/145 - Ignored files
	ignoredFiles = regexp.MustCompile(`(?i)(^|/)(desktop\.ini|thumbs\.db|\.ds_store|icon\r|\.dropbox|\.dropbox.attr)$`)
	// Upload chunk size - setting too small makes uploads slow.
	// Chunks aren't buffered into memory though so can set large.
	uploadChunkSize    = fs.SizeSuffix(128 * 1024 * 1024)
	maxUploadChunkSize = fs.SizeSuffix(150 * 1024 * 1024)
)

func NewClientForToken(accessToken string) *http.Client {
	oAuthConfig := &oauth2.Config{
		Scopes:   []string{},
		Endpoint: dropbox.OAuthEndpoint("")}

	t0, _ := time.Parse(time.RFC3339, timeutil.RFC3339Zero)

	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      t0}

	return oAuthConfig.Client(oauth2.NoContext, token)
}

// Fs represents a remote dropbox server
type Fs struct {
	name           string       // name of this remote
	root           string       // the path we are working on
	features       *fs.Features // optional features
	srv            files.Client // the connection to the dropbox server
	slashRoot      string       // root with "/" prefix, lowercase
	slashRootSlash string       // root with "/" prefix and postfix, lowercase
	pacer          *pacer.Pacer // To pace the API calls
}

// Object describes a dropbox object
//
// Dropbox Objects always have full metadata
type Object struct {
	fs      *Fs       // what this object is part of
	remote  string    // The remote path
	bytes   int64     // size of the object
	modTime time.Time // time it was last modified
	hash    string    // content_hash of the object
}

// ------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("Dropbox root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

func (f *Fs) SetToken(accessToken string) {
	oAuthClient := NewClientForToken(accessToken)

	config := dropbox.Config{
		Verbose: false,       // enables verbose logging in the SDK
		Client:  oAuthClient, // maybe???
	}
	f.srv = files.New(config)
}

func (f *Fs) SetTokenSimple(accessToken string) {
	f.srv = files.New(dropbox.Config{Token: accessToken, Verbose: true})
}

func NewFsToken(root string, accessToken string) *Fs {
	fs := &Fs{
		srv:   files.New(dropbox.Config{Token: accessToken, Verbose: true}),
		pacer: pacer.New().SetMinSleep(minSleep).SetMaxSleep(maxSleep).SetDecayConstant(decayConstant),
	}
	fs.setRoot(root)
	return fs
}

// Sets root in f
func (f *Fs) setRoot(root string) {
	f.root = strings.Trim(root, "/")
	lowerCaseRoot := strings.ToLower(f.root)

	f.slashRoot = "/" + lowerCaseRoot
	f.slashRootSlash = f.slashRoot
	if lowerCaseRoot != "" {
		f.slashRootSlash += "/"
	}
}

// getMetadata gets the metadata for a file or directory
func (f *Fs) getMetadata(objPath string) (entry files.IsMetadata, notFound bool, err error) {
	err = f.pacer.Call(func() (bool, error) {
		entry, err = f.srv.GetMetadata(&files.GetMetadataArg{Path: objPath})
		return shouldRetry(err)
	})
	if err != nil {
		switch e := err.(type) {
		case files.GetMetadataAPIError:
			switch e.EndpointError.Path.Tag {
			case files.LookupErrorNotFound:
				notFound = true
				err = nil
			}
		}
	}
	return
}

// getFileMetadata gets the metadata for a file
func (f *Fs) getFileMetadata(filePath string) (fileInfo *files.FileMetadata, err error) {
	entry, notFound, err := f.getMetadata(filePath)
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, fs.ErrorObjectNotFound
	}
	fileInfo, ok := entry.(*files.FileMetadata)
	if !ok {
		return nil, fs.ErrorNotAFile
	}
	return fileInfo, nil
}

// getDirMetadata gets the metadata for a directory
func (f *Fs) getDirMetadata(dirPath string) (dirInfo *files.FolderMetadata, err error) {
	entry, notFound, err := f.getMetadata(dirPath)
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, fs.ErrorDirNotFound
	}
	dirInfo, ok := entry.(*files.FolderMetadata)
	if !ok {
		return nil, fs.ErrorIsFile
	}
	return dirInfo, nil
}

func (f *Fs) SetRoot(dir string) {
	f.root = dir
	f.slashRoot = fmt.Sprintf("/%v", dir)
	f.slashRootSlash = fmt.Sprintf("/%v/", dir)
}

// shouldRetry returns a boolean as to whether this err deserves to be
// retried.  It returns the err as a convenience
func shouldRetry(err error) (bool, error) {
	if err == nil {
		return false, err
	}
	baseErrString := errors.Cause(err).Error()
	// FIXME there is probably a better way of doing this!
	if strings.Contains(baseErrString, "too_many_write_operations") || strings.Contains(baseErrString, "too_many_requests") {
		return true, err
	}
	return fs.ShouldRetry(err), err
}

// Return an Object from a path
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(remote string, info *files.FileMetadata) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	var err error
	if info != nil {
		err = o.setMetadataFromEntry(info)
	} else {
		err = o.readEntryAndSetMetadata()
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (f *Fs) List(dir string) (entries fs.DirEntries, err error) {
	root := f.slashRoot
	if dir != "" {
		root += "/" + dir
	}

	started := false
	//var res *files.ListFolderResult
	res := &files.ListFolderResult{}
	for {
		if !started {
			fmt.Println("NOT_STARTED")
			arg := files.ListFolderArg{
				Path:      root,
				Recursive: false,
			}
			if root == "/" {
				arg.Path = "" // Specify root folder as empty string
			}
			err = f.pacer.Call(func() (bool, error) {
				fmt.Println("HERE")
				res, err = f.srv.ListFolder(&arg)
				return shouldRetry(err)
			})
			if err != nil {
				switch e := err.(type) {
				case files.ListFolderAPIError:
					switch e.EndpointError.Path.Tag {
					case files.LookupErrorNotFound:
						err = fs.ErrorDirNotFound
					}
				}
				return nil, err
			}
			fmt.Println("HERE2")
			started = true
		} else {
			arg := files.ListFolderContinueArg{
				Cursor: res.Cursor,
			}
			err = f.pacer.Call(func() (bool, error) {
				res, err = f.srv.ListFolderContinue(&arg)
				return shouldRetry(err)
			})
			if err != nil {
				return nil, errors.Wrap(err, "list continue")
			}
		}
		for _, entry := range res.Entries {
			var fileInfo *files.FileMetadata
			var folderInfo *files.FolderMetadata
			var metadata *files.Metadata
			switch info := entry.(type) {
			case *files.FolderMetadata:
				folderInfo = info
				metadata = &info.Metadata
			case *files.FileMetadata:
				fileInfo = info
				metadata = &info.Metadata
			default:
				fs.Errorf(f, "Unknown type %T", entry)
				continue
			}
			// Only the last element is reliably cased in PathDisplay
			entryPath := metadata.PathDisplay
			leaf := path.Base(entryPath)
			remote := path.Join(dir, leaf)
			if folderInfo != nil {
				d := fs.NewDir(remote, time.Now())
				entries = append(entries, d)
			} else if fileInfo != nil {
				o, err := f.newObjectWithInfo(remote, fileInfo)
				if err != nil {
					return nil, err
				}
				entries = append(entries, o)
			}
		}
		if !res.HasMore {
			break
		}
	}
	return entries, nil
}

// A read closer which doesn't close the input
type readCloser struct {
	in io.Reader
}

// Read bytes from the object - see io.Reader
func (rc *readCloser) Read(p []byte) (n int, err error) {
	return rc.in.Read(p)
}

// Dummy close function
func (rc *readCloser) Close() error {
	return nil
}

// Put the object
//
// Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *Fs) Put(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Temporary Object under construction
	o := &Object{
		fs:     f,
		remote: src.Remote(),
	}
	return o, o.Update(in, src, options...)
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
func (f *Fs) PutStream(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(in, src, options...)
}

// Mkdir creates the container if it doesn't exist
func (f *Fs) Mkdir(dir string) error {
	root := path.Join(f.slashRoot, dir)

	// can't create or run metadata on root
	if root == "/" {
		return nil
	}

	// check directory doesn't exist
	_, err := f.getDirMetadata(root)
	if err == nil {
		return nil // directory exists already
	} else if err != fs.ErrorDirNotFound {
		return err // some other error
	}

	// create it
	arg2 := files.CreateFolderArg{
		Path: root,
	}
	err = f.pacer.Call(func() (bool, error) {
		_, err = f.srv.CreateFolderV2(&arg2)
		return shouldRetry(err)
	})
	return err
}

// Precision returns the precision
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() fs.HashSet {
	return fs.HashSet(fs.HashDropbox)
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the dropbox special hash
func (o *Object) Hash(t fs.HashType) (string, error) {
	if t != fs.HashDropbox {
		return "", fs.ErrHashUnsupported
	}
	err := o.readMetaData()
	if err != nil {
		return "", errors.Wrap(err, "failed to read hash from metadata")
	}
	return o.hash, nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.bytes
}

// setMetadataFromEntry sets the fs data from a files.FileMetadata
//
// This isn't a complete set of metadata and has an inacurate date
func (o *Object) setMetadataFromEntry(info *files.FileMetadata) error {
	o.bytes = int64(info.Size)
	o.modTime = info.ClientModified
	o.hash = info.ContentHash
	return nil
}

// Reads the entry for a file from dropbox
func (o *Object) readEntry() (*files.FileMetadata, error) {
	return o.fs.getFileMetadata(o.remotePath())
}

// Read entry if not set and set metadata from it
func (o *Object) readEntryAndSetMetadata() error {
	// Last resort set time from client
	if !o.modTime.IsZero() {
		return nil
	}
	entry, err := o.readEntry()
	if err != nil {
		return err
	}
	return o.setMetadataFromEntry(entry)
}

// Returns the remote path for the object
func (o *Object) remotePath() string {
	return o.fs.slashRootSlash + o.remote
}

// Returns the key for the metadata database for a given path
func metadataKey(path string) string {
	// NB File system is case insensitive
	path = strings.ToLower(path)
	hash := md5.New()
	_, _ = hash.Write([]byte(path))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Returns the key for the metadata database
func (o *Object) metadataKey() string {
	return metadataKey(o.remotePath())
}

// readMetaData gets the info if it hasn't already been fetched
func (o *Object) readMetaData() (err error) {
	if !o.modTime.IsZero() {
		return nil
	}
	// Last resort
	return o.readEntryAndSetMetadata()
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime() time.Time {
	err := o.readMetaData()
	if err != nil {
		fs.Debugf(o, "Failed to read metadata: %v", err)
		return time.Now()
	}
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
//
// Commits the datastore
func (o *Object) SetModTime(modTime time.Time) error {
	// Dropbox doesn't have a way of doing this so returning this
	// error will cause the file to be deleted first then
	// re-uploaded to set the time.
	return fs.ErrorCantSetModTimeWithoutDelete
}

// Storable returns whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(options ...fs.OpenOption) (in io.ReadCloser, err error) {
	headers := fs.OpenOptionHeaders(options)
	arg := files.DownloadArg{Path: o.remotePath(), ExtraHeaders: headers}
	err = o.fs.pacer.Call(func() (bool, error) {
		_, in, err = o.fs.srv.Download(&arg)
		return shouldRetry(err)
	})

	switch e := err.(type) {
	case files.DownloadAPIError:
		// Don't attempt to retry copyright violation errors
		if e.EndpointError.Path.Tag == files.LookupErrorRestrictedContent {
			return nil, fs.NoRetryError(err)
		}
	}

	return
}

// uploadChunked uploads the object in parts
//
// Will work optimally if size is >= uploadChunkSize. If the size is either
// unknown (i.e. -1) or smaller than uploadChunkSize, the method incurs an
// avoidable request to the Dropbox API that does not carry payload.
//
// FIXME buffer chunks to improve upload retries
func (o *Object) uploadChunked(in0 io.Reader, commitInfo *files.CommitInfo, size int64) (entry *files.FileMetadata, err error) {
	chunkSize := int64(uploadChunkSize)
	chunks := 0
	if size != -1 {
		chunks = int(size/chunkSize) + 1
	}
	in := fs.NewCountingReader(in0)

	fmtChunk := func(cur int, last bool) {
		if chunks == 0 && last {
			fs.Debugf(o, "Streaming chunk %d/%d", cur, cur)
		} else if chunks == 0 {
			fs.Debugf(o, "Streaming chunk %d/unknown", cur)
		} else {
			fs.Debugf(o, "Uploading chunk %d/%d", cur, chunks)
		}
	}

	// write the first chunk
	fmtChunk(1, false)
	var res *files.UploadSessionStartResult
	err = o.fs.pacer.CallNoRetry(func() (bool, error) {
		res, err = o.fs.srv.UploadSessionStart(&files.UploadSessionStartArg{}, &io.LimitedReader{R: in, N: chunkSize})
		return shouldRetry(err)
	})
	if err != nil {
		return nil, err
	}

	cursor := files.UploadSessionCursor{
		SessionId: res.SessionId,
		Offset:    0,
	}
	appendArg := files.UploadSessionAppendArg{
		Cursor: &cursor,
		Close:  false,
	}

	// write more whole chunks (if any)
	currentChunk := 2
	for {
		if chunks > 0 && currentChunk >= chunks {
			// if the size is known, only upload full chunks. Remaining bytes are uploaded with
			// the UploadSessionFinish request.
			break
		} else if chunks == 0 && in.BytesRead()-cursor.Offset < uint64(chunkSize) {
			// if the size is unknown, upload as long as we can read full chunks from the reader.
			// The UploadSessionFinish request will not contain any payload.
			break
		}
		cursor.Offset = in.BytesRead()
		fmtChunk(currentChunk, false)
		err = o.fs.pacer.CallNoRetry(func() (bool, error) {
			err = o.fs.srv.UploadSessionAppendV2(&appendArg, &io.LimitedReader{R: in, N: chunkSize})
			return shouldRetry(err)
		})
		if err != nil {
			return nil, err
		}
		currentChunk++
	}

	// write the remains
	cursor.Offset = in.BytesRead()
	args := &files.UploadSessionFinishArg{
		Cursor: &cursor,
		Commit: commitInfo,
	}
	fmtChunk(currentChunk, true)
	err = o.fs.pacer.CallNoRetry(func() (bool, error) {
		entry, err = o.fs.srv.UploadSessionFinish(args, in)
		return shouldRetry(err)
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// Update the already existing object
//
// Copy the reader into the object updating modTime and size
//
// The new object may have been created if an error is returned
func (o *Object) Update(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	remote := o.remotePath()
	if ignoredFiles.MatchString(remote) {
		fs.Logf(o, "File name disallowed - not uploading")
		return nil
	}
	commitInfo := files.NewCommitInfo(o.remotePath())
	commitInfo.Mode.Tag = "overwrite"
	// The Dropbox API only accepts timestamps in UTC with second precision.
	commitInfo.ClientModified = src.ModTime().UTC().Round(time.Second)

	size := src.Size()
	var err error
	var entry *files.FileMetadata
	if size > int64(uploadChunkSize) || size == -1 {
		entry, err = o.uploadChunked(in, commitInfo, size)
	} else {
		err = o.fs.pacer.CallNoRetry(func() (bool, error) {
			entry, err = o.fs.srv.Upload(commitInfo, in)
			return shouldRetry(err)
		})
	}
	if err != nil {
		return errors.Wrap(err, "upload failed")
	}
	return o.setMetadataFromEntry(entry)
}

// Remove an object
func (o *Object) Remove() (err error) {
	err = o.fs.pacer.CallNoRetry(func() (bool, error) {
		_, err = o.fs.srv.DeleteV2(&files.DeleteArg{Path: o.remotePath()})
		return shouldRetry(err)
	})
	return err
}

/*
// Check the interfaces are satisfied
var (
	_ fs.Fs          = (*Fs)(nil)
	_ fs.Copier      = (*Fs)(nil)
	_ fs.Purger      = (*Fs)(nil)
	_ fs.PutStreamer = (*Fs)(nil)
	_ fs.Mover       = (*Fs)(nil)
	_ fs.DirMover    = (*Fs)(nil)
	_ fs.Object      = (*Object)(nil)
)
*/
