package db

import (
	"main/internal/mongostore"
	"os"
	"strings"
	"sync"
)

var sharedDB *mongostore.DB
var sharedDBMu sync.Mutex

func GetDB() (*mongostore.DB, error) {
	sharedDBMu.Lock()
	defer sharedDBMu.Unlock()
	if sharedDB != nil {
		return sharedDB, nil
	}
	name := strings.TrimSpace(os.Getenv("MONGODB_DATABASE"))
	if name == "" {
		name = "Main_Database"
	}
	d, err := mongostore.Open(os.Getenv("MONGODB_URI"), name, "records")
	if err != nil {
		return nil, err
	}
	sharedDB = d
	return d, nil
}
func CloseDB() error {
	sharedDBMu.Lock()
	defer sharedDBMu.Unlock()
	if sharedDB == nil {
		return nil
	}
	err := sharedDB.Close()
	sharedDB = nil
	return err
}
