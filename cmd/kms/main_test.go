package main

import (
	"strings"
	"testing"
)

func TestResolvePutValue(t *testing.T) {
	tests := []struct {
		name      string
		subArgs   []string
		useStdin  bool
		stdin     string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "positional value",
			subArgs: []string{"providers/square/dev/access_token", "sq_secret_123"},
			want:    "sq_secret_123",
		},
		{
			name:     "stdin value",
			subArgs:  []string{"providers/square/dev/access_token"},
			useStdin: true,
			stdin:    "sq_secret_from_stdin",
			want:     "sq_secret_from_stdin",
		},
		{
			name:     "stdin strips single trailing LF",
			subArgs:  []string{"a/b"},
			useStdin: true,
			stdin:    "value\n",
			want:     "value",
		},
		{
			name:     "stdin strips trailing CRLF",
			subArgs:  []string{"a/b"},
			useStdin: true,
			stdin:    "value\r\n",
			want:     "value",
		},
		{
			name:     "stdin preserves inner whitespace",
			subArgs:  []string{"a/b"},
			useStdin: true,
			stdin:    "multi line\nvalue\n",
			want:     "multi line\nvalue",
		},
		{
			name:      "rejects both positional and stdin",
			subArgs:   []string{"a/b", "pos_val"},
			useStdin:  true,
			stdin:     "stdin_val",
			wantErr:   true,
			errSubstr: "cannot combine positional",
		},
		{
			name:      "empty stdin rejected",
			subArgs:   []string{"a/b"},
			useStdin:  true,
			stdin:     "",
			wantErr:   true,
			errSubstr: "empty value",
		},
		{
			name:      "missing path",
			subArgs:   []string{},
			wantErr:   true,
			errSubstr: "requires <path/name>",
		},
		{
			name:      "missing value without stdin",
			subArgs:   []string{"a/b"},
			wantErr:   true,
			errSubstr: "requires <path/name> <value>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePutValue(tt.subArgs, tt.useStdin, "put", strings.NewReader(tt.stdin))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("value = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractBoolFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flag     string
		wantVal  bool
		wantArgs []string
	}{
		{
			name:     "flag present at end",
			args:     []string{"put", "path/name", "--stdin"},
			flag:     "--stdin",
			wantVal:  true,
			wantArgs: []string{"put", "path/name"},
		},
		{
			name:     "flag present at middle",
			args:     []string{"put", "--stdin", "path/name"},
			flag:     "--stdin",
			wantVal:  true,
			wantArgs: []string{"put", "path/name"},
		},
		{
			name:     "flag absent",
			args:     []string{"put", "path/name", "value"},
			flag:     "--stdin",
			wantVal:  false,
			wantArgs: []string{"put", "path/name", "value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := false
			out := extractBoolFlag(&got, tt.args, tt.flag)
			if got != tt.wantVal {
				t.Errorf("val = %v, want %v", got, tt.wantVal)
			}
			if len(out) != len(tt.wantArgs) {
				t.Fatalf("len = %d, want %d", len(out), len(tt.wantArgs))
			}
			for i := range out {
				if out[i] != tt.wantArgs[i] {
					t.Errorf("args[%d] = %q, want %q", i, out[i], tt.wantArgs[i])
				}
			}
		})
	}
}
