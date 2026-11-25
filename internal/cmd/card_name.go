// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

// withCardName names the key on its wallet card ("app_name", the card's
// heading), keeping what the approval's context already says (its summary,
// the kind of key). Every binding-v2 card for a key (create, delete,
// delete_after, update_policy_from) reads alike; without a name the wallet
// falls back to the handle.
func withCardName(ctx map[string]string, name string) map[string]string {
	out := make(map[string]string, len(ctx)+1)
	for k, v := range ctx {
		out[k] = v
	}
	if name != "" {
		out["app_name"] = name
	}
	return out
}
