package urlauth

import (
	"testing"
	"time"
)

var (
	startTime      = time.Unix(1538596988, 0)
	expirationTime = time.Unix(1854215610, 0)
)

func TestSignURL(t *testing.T) {
	type args struct {
		url            string
		secret         string
		secretID       int
		ignoredParams  []string
		startTime      *time.Time
		expirationTime *time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "Empty URL",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "Empty secret",
			args:    args{url: "https://www.example.com/foo"},
			wantErr: true,
		},
		{
			name: "Invalid URL",
			args: args{
				url:    "*&#$%",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL",
			args: args{
				url:    "https://www.example.com/foo?client_id=abc123",
				secret: "supersecret",
			},
			want: "https://www.example.com/foo?client_id=abc123&encoded=03c29a7f6fe513d1815a3",
		},
		{
			name: "Valid URL with expiration time",
			args: args{
				url:            "https://www.example.com/foo?client_id=abc123",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?client_id=abc123&encoded=0125a220f566a3e0f2e35&etime=20281003195330",
		},
		{
			name: "Valid URL with start time",
			args: args{
				url:       "https://www.example.com/foo?client_id=abc123",
				secret:    "supersecret",
				startTime: &startTime,
			},
			want: "https://www.example.com/foo?client_id=abc123&encoded=002dfbf07b5e391710ab0&stime=20181003200308",
		},
		{
			name: "Valid URL with start and expiration time",
			args: args{
				url:            "https://www.example.com/foo?client_id=abc123",
				secret:         "supersecret",
				startTime:      &startTime,
				expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?client_id=abc123&encoded=0b70b20e3b1087dcc0d8b&etime=20281003195330&stime=20181003200308",
		},
		{
			name: "Valid URL with excluded params",
			args: args{
				url:            "https://www.example.com/foo?client_id=abc123",
				secret:         "supersecret",
				startTime:      &startTime,
				expirationTime: &expirationTime,
				ignoredParams:  []string{"client_id"},
			},
			want: "https://www.example.com/foo?client_id=abc123&encoded=0eaf0da0e6e3290bc6b15&etime=20281003195330&stime=20181003200308",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignURL(tt.args.url, tt.args.secret, tt.args.secretID, tt.args.ignoredParams, tt.args.startTime, tt.args.expirationTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
