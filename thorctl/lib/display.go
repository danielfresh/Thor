/*
Copyright 2016 The Thorctl Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lib

import (
	"text/tabwriter"
	"os"
	"fmt"
	"io"
)

var (
	w = tabwriter.NewWriter(os.Stdout, 20, 1, 3, ' ', 0)
)

func Display(content string, header string, clear bool) {

	if clear {
		fmt.Fprint(os.Stdout, "\033[2J")
		fmt.Fprint(os.Stdout, "\033[H")
	}

	// io.WriteString(w, "CONTAINER\tCPU %\tMEM USAGE / LIMIT\tMEM %\tNET I/O\tBLOCK I/O\tPIDS\n")
	io.WriteString(w, header)

	//format := "%s\t%.2f%%\t%s / %s\t%.2f%%\t%s / %s\t%s / %s\t%d\n"

	fmt.Fprint(w, content)

	w.Flush()
}