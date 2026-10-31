package scraper

import (
	"regexp"
	"sort"
	"strings"
)

type Intent struct {
	Title      string
	Genres     string
	Countries  string
	ForcedType string
	Keywords   string
	Languages  string
}

type originHit struct {
	Country    string
	ForcedType string
}

var originMap = map[string]originHit{
	"kdrama":        {"KR", ""},
	"korean drama":  {"KR", ""},
	"korean movie":  {"KR", "feature"},
	"korean":        {"KR", ""},
	"kpop":          {"KR", ""},
	"bollywood":     {"IN", "feature"},
	"hindi":         {"IN", ""},
	"indian":        {"IN", ""},
	"turkish":       {"TR", ""},
	"turkish drama": {"TR", ""},
	"anime":         {"JP", ""},
	"japanese":      {"JP", ""},
	"chinese drama": {"CN", ""},
	"cdrama":        {"CN", ""},
	"thai drama":    {"TH", ""},
	"spanish":       {"ES", ""},
	"french":        {"FR", ""},
	"german":        {"DE", ""},
	"italian":       {"IT", ""},
	"israeli":       {"IL", ""},
	"british":       {"GB", ""},
}

var keywordSet = map[string]struct{}{
	"kdrama": {}, "korean drama": {}, "kpop": {}, "cdrama": {}, "anime": {}, "thai drama": {},
	"disney": {}, "disney original": {}, "disney plus": {}, "disney+": {},
	"pixar": {}, "marvel": {}, "marvel studios": {}, "mcu": {},
	"dc": {}, "dc comics": {}, "dceu": {}, "warner bros": {}, "warner brothers": {},
	"universal": {}, "paramount": {}, "sony pictures": {}, "20th century fox": {},
	"lionsgate": {}, "miramax": {}, "studio ghibli": {}, "ghibli": {}, "dreamworks": {},
	"blumhouse": {}, "a24": {}, "neon": {}, "hbo": {}, "showtime": {},
	"netflix": {}, "netflix original": {}, "amazon prime": {}, "prime video": {},
	"hulu": {}, "hbo max": {}, "max": {}, "apple tv": {}, "apple tv+": {}, "appletv": {},
	"disney plus original": {}, "peacock": {}, "paramount plus": {}, "paramount+": {},
	"starz": {}, "crunchyroll": {}, "funimation": {},
	"star wars": {}, "harry potter": {}, "lord of the rings": {}, "lotr": {},
	"james bond": {}, "007": {}, "fast and furious": {}, "mission impossible": {},
	"transformers": {}, "jurassic park": {}, "jurassic world": {},
	"avengers": {}, "x-men": {}, "spider-man": {}, "spiderman": {}, "batman": {},
	"superman": {}, "wonder woman": {}, "justice league": {},
	"pokemon": {}, "dragon ball": {}, "naruto": {}, "one piece": {},
	"classic film": {}, "old hollywood": {}, "golden age": {}, "silent era": {},
	"blockbuster": {}, "indie film": {}, "indie movie": {}, "art house": {}, "arthouse": {},
	"b movie": {}, "b-movie": {}, "exploitation": {}, "grindhouse": {},
	"found footage": {}, "mockumentary": {}, "based on true story": {},
	"based on a true story": {}, "true story": {}, "biopic": {},
	"christmas": {}, "christmas movie": {}, "halloween": {}, "thanksgiving": {},
	"valentine": {}, "easter": {}, "summer blockbuster": {},
	"kids movie": {}, "family friendly": {}, "teen": {}, "teen movie": {},
	"young adult": {}, "ya": {},
}

var languageMap = map[string]string{
	"malayalam": "ml", "tamil": "ta", "telugu": "te", "kannada": "kn", "punjabi": "pa",
	"hindi": "hi", "marathi": "mr", "gujarati": "gu", "bengali": "bn", "odia": "or",
	"korean": "ko", "chinese": "zh", "japanese": "ja", "thai": "th", "vietnamese": "vi",
	"tagalog": "tl", "indonesian": "id", "malay": "ms", "burmese": "my", "laotian": "lo",
	"khmer": "km", "mongolian": "mn", "tibetan": "bo",
	"spanish": "es", "french": "fr", "german": "de", "italian": "it", "portuguese": "pt",
	"polish": "pl", "dutch": "nl", "greek": "el", "russian": "ru", "czech": "cs",
	"hungarian": "hu", "romanian": "ro", "bulgarian": "bg", "croatian": "hr", "serbian": "sr",
	"ukrainian": "uk", "swedish": "sv", "norwegian": "no", "danish": "da", "finnish": "fi",
	"arabic": "ar", "hebrew": "he", "persian": "fa", "urdu": "ur", "swahili": "sw",
	"afrikaans": "af", "amharic": "am", "yoruba": "yo", "somali": "so", "turkish": "tr",
}

var genreMap = map[string]string{
	"action": "action", "comedy": "comedy", "horror": "horror", "thriller": "thriller",
	"romance": "romance", "sci-fi": "sci_fi", "scifi": "sci_fi", "science fiction": "sci_fi",
	"drama": "drama", "fantasy": "fantasy", "mystery": "mystery", "crime": "crime",
	"adventure": "adventure", "animation": "animation", "animated": "animation",
	"documentary": "documentary", "family": "family", "biography": "biography",
	"history": "history", "musical": "music", "music": "music",
	"war": "war", "western": "western", "sport": "sport", "sports": "sport",
	"superhero": "superhero", "superhero film": "superhero", "superhero movie": "superhero",
	"romantic comedy": "romance", "rom-com": "romance", "romcom": "romance",
	"suspense": "thriller", "suspenseful": "thriller",
	"psychological": "thriller", "psychological thriller": "thriller",
	"dark": "thriller", "dark comedy": "comedy", "dark humor": "comedy",
	"indie": "indie", "independent": "indie",
	"cult": "cult_film", "cult film": "cult_film",
	"experimental": "experimental",
	"art":          "art_film", "art film": "art_film",
	"silent": "silent_film", "silent film": "silent_film",
	"classic": "classic", "classical": "classic",
	"noir": "film_noir", "film noir": "film_noir",
	"slasher": "horror", "monster": "horror", "vampire": "horror", "zombie": "horror",
	"ghost": "horror", "paranormal": "horror",
	"supernatural": "fantasy", "magic": "fantasy", "sorcery": "fantasy",
	"sword and sorcery": "fantasy", "fairy tale": "fantasy",
	"mythology": "fantasy", "mythological": "fantasy",
	"superhero action": "action",
	"heist":            "crime", "heist film": "crime",
	"detective": "mystery", "whodunit": "mystery", "noir mystery": "mystery",
	"spy": "thriller", "espionage": "thriller", "government": "thriller",
	"political": "drama", "politics": "drama",
	"social": "drama", "social drama": "drama", "sociological": "drama",
	"religious": "drama", "faith": "drama",
	"coming of age": "drama", "coming-of-age": "drama",
	"youth": "drama", "teenage": "drama", "school": "drama", "campus": "drama", "university": "drama",
	"love": "romance", "romantic": "romance", "couple": "romance",
	"relationship": "drama", "family drama": "drama",
	"family film": "family", "kids": "family", "children": "family",
	"kids film": "family", "children film": "family",
	"animation adventure": "adventure", "adventure action": "action",
	"action adventure": "action", "action romance": "action",
	"action comedy":  "comedy",
	"thriller drama": "drama", "drama romance": "romance", "comedy drama": "drama",
}

var typeMap = map[string]string{
	"movie":       "feature",
	"movies":      "feature",
	"film":        "feature",
	"films":       "feature",
	"series":      "tv_series",
	"show":        "tv_series",
	"shows":       "tv_series",
	"tv show":     "tv_series",
	"tv series":   "tv_series",
	"miniseries":  "mini_series",
	"documentary": "documentary",
	"short film":  "short",
	"short":       "short",
	"anime":       "tv_series",
}

var (
	originKeysDesc   = sortedByLenDesc(originMap)
	genreKeysDesc    = sortedByLenDesc(genreMap)
	languageKeysDesc = sortedByLenDesc(languageMap)
	typeKeysDesc     = sortedByLenDesc(typeMap)
)

var whitespaceRe = regexp.MustCompile(`\s+`)

func sortedByLenDesc[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	return keys
}

func wordBoundaryRe(word string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(word) + `\b`)
}

func ParseIntent(query string) Intent {
	q := strings.ToLower(strings.TrimSpace(query))

	var (
		countries  string
		forcedType string
		genres     []string
		keywords   []string
		languages  []string
	)

	for _, kw := range originKeysDesc {
		re := wordBoundaryRe(kw)
		if re.MatchString(q) {
			hit := originMap[kw]
			countries = hit.Country
			forcedType = hit.ForcedType
			if _, ok := keywordSet[kw]; ok {
				keywords = append(keywords, kw)
			}
			q = strings.TrimSpace(re.ReplaceAllString(q, ""))
			break
		}
	}

	for _, lang := range languageKeysDesc {
		re := wordBoundaryRe(lang)
		if re.MatchString(q) {
			languages = append(languages, languageMap[lang])
			q = strings.TrimSpace(re.ReplaceAllString(q, ""))
		}
	}

	for _, kw := range genreKeysDesc {
		re := wordBoundaryRe(kw)
		if re.MatchString(q) {
			genres = append(genres, genreMap[kw])
			q = strings.TrimSpace(re.ReplaceAllString(q, ""))
		}
	}

	if forcedType == "" {
		for _, kw := range typeKeysDesc {
			re := wordBoundaryRe(kw)
			if re.MatchString(q) {
				forcedType = typeMap[kw]
				q = strings.TrimSpace(re.ReplaceAllString(q, ""))
				break
			}
		}
	}

	title := strings.TrimSpace(whitespaceRe.ReplaceAllString(q, " "))

	return Intent{
		Title:      title,
		Genres:     strings.Join(genres, ","),
		Countries:  countries,
		ForcedType: forcedType,
		Keywords:   strings.Join(keywords, ","),
		Languages:  strings.Join(languages, ","),
	}
}
