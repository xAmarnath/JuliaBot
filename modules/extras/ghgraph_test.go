package extras

import (
	"image/png"
	"os"
	"testing"
	"time"
)

func TestGHGraphLiveRender(t *testing.T) {
	if os.Getenv("SERVICES_LIVE") == "" {
		t.Skip("set SERVICES_LIVE=1")
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir("modules/extras")
	for _, user := range []string{"AmarnathCJD", "torvalds"} {
		u, err := ghFetchUser(user)
		if err != nil {
			t.Fatal(err)
		}
		d := &ghGraphData{User: *u}
		d.Created, _ = time.Parse(time.RFC3339, u.CreatedAt)
		d.Repos, _ = ghFetchAllRepos(u.Login)
		if c, _, err := ghContribFetch(u.Login); err == nil {
			d.Days, d.Total = ghContribFlatten(c.Contributions), c.TotalContributions
		}
		d.Avatar = ghFetchAvatar(u.AvatarURL)
		img, err := renderGHGraph(d)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := os.Create(os.TempDir() + "/ghgraph_" + user + ".png")
		png.Encode(f, img)
		f.Close()
	}
}

func TestGHGraphEmptyUserRenders(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir("modules/extras")
	if _, err := renderGHGraph(&ghGraphData{User: ghUser{Login: "newbie"}}); err != nil {
		t.Fatal(err)
	}
}
