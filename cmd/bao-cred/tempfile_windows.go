package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createSecureTemp(directory string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}

	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}

	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	for range 100 {
		var randomName [16]byte
		if _, err := rand.Read(randomName[:]); err != nil {
			return nil, err
		}

		path := filepath.Join(directory, ".bao-cred-"+hex.EncodeToString(randomName[:]))
		pathPointer, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}

		handle, err := windows.CreateFile(
			pathPointer,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			&attributes,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(handle), path), nil
	}

	return nil, fmt.Errorf("create unique temporary file in %q", directory)
}
