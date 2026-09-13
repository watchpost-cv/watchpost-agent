//go:build !unix

package main

import "os"

func restoreFileOwner(string, os.FileInfo) error { return nil }
