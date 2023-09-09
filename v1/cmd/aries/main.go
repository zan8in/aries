package main

import (
	"io"
	"os"

	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
)

const (
	NEW_FILE_PERM = 0666
)

// AppendString appends the contents of the string to filename.
func AppendString(filename, content string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, NEW_FILE_PERM)
	if err != nil {
		return err
	}
	data := []byte(content)
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
		// fmt.Println(err)
	}
	if err1 := f.Close(); err == nil {
		err = err1
		// fmt.Println(err)
	}
	return err
}

func main() {
	// for i := 170; i <= 254; i++ {
	// 	for j := 1; j <= 254; j++ {
	// 		text := fmt.Sprintf("13.130.%d.%d\n", i, j)
	// 		fmt.Println(text)
	// 		AppendString("ips.txt", text)
	// 	}
	// }

	// return

	options := aries.ParseOptions()

	runner, err := aries.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	runner.OnResult = func(r aries.Result) {
		gologger.Print().Msgf("%s:%d\n", r.Host, r.Port)
	}

	err = runner.Run()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	runner.Start()

}
