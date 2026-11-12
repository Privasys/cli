// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The key file holds the secret as shell exports; the printed recipe names the
// file and never the secret.
func TestBackupAccessFileAndRecipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.env")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBackupAccessFile(f, "app-1", "AKID", "s3cr'et"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	for _, want := range []string{"export AWS_ACCESS_KEY_ID='AKID'\n", `export AWS_SECRET_ACCESS_KEY='s3cr'\''et'` + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %q:\n%s", want, got)
		}
	}

	recipe := kopiaRecipe(path, map[string]interface{}{
		"access_key_id": "AKID", "bucket": "b", "endpoint": "s3.gra.io.cloud.ovh.net", "region": "gra", "prefix": "apps/app-1/",
	})
	if strings.Contains(recipe, "s3cr") {
		t.Error("the recipe shows the secret")
	}
	if !strings.Contains(recipe, "--bucket=b --endpoint=s3.gra.io.cloud.ovh.net --region=gra --prefix=apps/app-1/ --readonly") {
		t.Errorf("recipe:\n%s", recipe)
	}
}
