package scraper

import "context"

type Image struct {
	ID      *string `json:"id"`
	URL     string  `json:"url"`
	Width   *int    `json:"width"`
	Height  *int    `json:"height"`
	Caption *string `json:"caption"`
}

type ImagesResult struct {
	Total        *int    `json:"total"`
	PrimaryImage *Image  `json:"primary_image"`
	Images       []Image `json:"images"`
}

func (s *Scraper) GetImages(ctx context.Context, imdbID string, limit int) (*ImagesResult, error) {
	url := baseURL + "/title/" + imdbID + "/mediaindex/"
	body, err := s.FetchHTML(ctx, url)
	if err != nil {
		return nil, err
	}
	if body == "" {
		return nil, nil
	}
	nd := extractNextData(body)
	if nd == nil {
		return nil, nil
	}
	title := walkMap(nd, "props", "pageProps", "contentData", "data", "title")
	if title == nil {
		return nil, nil
	}

	allImages := walkMap(title, "all_images")
	edges := walkList(allImages, "edges")
	total := walkInt(allImages, "total")

	primary := walkMap(title, "primaryImage")
	var primaryImage *Image
	if primary != nil {
		if pURL := walkString(primary, "url"); pURL != "" {
			img := Image{URL: pURL}
			if id := walkString(primary, "id"); id != "" {
				img.ID = &id
			}
			img.Width = walkInt(primary, "width")
			img.Height = walkInt(primary, "height")
			if cap := walkString(primary, "caption", "plainText"); cap != "" {
				img.Caption = &cap
			}
			primaryImage = &img
		}
	}

	if limit < 1 {
		limit = 1
	}
	images := make([]Image, 0, limit)
	for i, e := range edges {
		if i >= limit {
			break
		}
		node := walkMap(e, "node")
		if node == nil {
			continue
		}
		u := walkString(node, "url")
		if u == "" {
			continue
		}
		img := Image{URL: u}
		if id := walkString(node, "id"); id != "" {
			img.ID = &id
		}
		img.Width = walkInt(node, "width")
		img.Height = walkInt(node, "height")
		if cap := walkString(node, "caption", "plainText"); cap != "" {
			img.Caption = &cap
		}
		images = append(images, img)
	}

	if len(images) == 0 && primaryImage == nil {
		return nil, nil
	}

	return &ImagesResult{
		Total:        total,
		PrimaryImage: primaryImage,
		Images:       images,
	}, nil
}
