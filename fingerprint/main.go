package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/andrewstucki/fingerprint"
)

const helpString = `Fingerprint a file or directory.

Usage: %s [filename|directory]
`

func help(name string) {
	fmt.Printf(helpString, name)
}

type file struct {
	Name string `json:"name"`
	*fingerprint.Info
}

func main() {
	if len(os.Args) != 2 {
		help(os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("File '%s' not found", filename)
			os.Exit(1)
		}
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()

	fileinfo, err := f.Stat()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var files []file
	if fileinfo.IsDir() {
		files, err = fingerprintDirectory(f)
	} else {
		files, err = fingerprintFile(f, fileinfo.Size())
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	data, err := json.Marshal(files)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func fingerprintDirectory(dir *os.File) ([]file, error) {
	var mutex sync.Mutex
	files := []file{}

	pool := newPool(runtime.NumCPU())
	defer pool.Release()
	if err := filepath.Walk(dir.Name(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		isSymlink := info.Mode()&os.ModeSymlink > 0
		isEmpty := info.Size() == 0
		if !info.IsDir() && !isSymlink && !isEmpty {
			pool.Enqueue(func() {
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unable to read '%s': %v\n", path, err)
					return
				}
				defer f.Close()
				info, err := fingerprint.Parse(f, int(info.Size()))
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unable to fingerprint '%s': %v\n", path, err)
					return
				}
				mutex.Lock()
				files = append(files, file{Info: info, Name: path})
				mutex.Unlock()
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	pool.Wait()

	return files, nil
}

func fingerprintFile(f *os.File, size int64) ([]file, error) {
	info, err := fingerprint.Parse(f, int(size))
	if err != nil {
		return nil, err
	}
	return []file{
		file{Info: info, Name: f.Name()},
	}, nil
}
