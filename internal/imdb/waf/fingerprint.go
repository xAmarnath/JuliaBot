package waf

import (
	"math/rand/v2"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"
)

type fpMetrics struct {
	Fp2          int `json:"fp2"`
	Browser      int `json:"browser"`
	Capabilities int `json:"capabilities"`
	Gpu          int `json:"gpu"`
	Dnt          int `json:"dnt"`
	Math         int `json:"math"`
	Screen       int `json:"screen"`
	Navigator    int `json:"navigator"`
	Auto         int `json:"auto"`
	Stealth      int `json:"stealth"`
	Subtle       int `json:"subtle"`
	Canvas       int `json:"canvas"`
	Formdetector int `json:"formdetector"`
	Be           int `json:"be"`
}

type fpPlugin struct {
	Name string `json:"name"`
	Str  string `json:"str"`
}

type fpCSS struct {
	TextShadow       int `json:"textShadow"`
	WebkitTextStroke int `json:"WebkitTextStroke"`
	BoxShadow        int `json:"boxShadow"`
	BorderRadius     int `json:"borderRadius"`
	BorderImage      int `json:"borderImage"`
	Opacity          int `json:"opacity"`
	Transform        int `json:"transform"`
	Transition       int `json:"transition"`
}

type fpJS struct {
	Audio        bool   `json:"audio"`
	Geolocation  bool   `json:"geolocation"`
	LocalStorage string `json:"localStorage"`
	Touch        bool   `json:"touch"`
	Video        bool   `json:"video"`
	WebWorker    bool   `json:"webWorker"`
}

type fpCapabilities struct {
	CSS     fpCSS `json:"css"`
	JS      fpJS  `json:"js"`
	Elapsed int   `json:"elapsed"`
}

type fpGPU struct {
	Vendor     string   `json:"vendor"`
	Model      string   `json:"model"`
	Extensions []string `json:"extensions"`
}

type fpMath struct {
	Tan string `json:"tan"`
	Sin string `json:"sin"`
	Cos string `json:"cos"`
}

type fpProperties struct {
	Document  []any `json:"document"`
	Window    []any `json:"window"`
	Navigator []any `json:"navigator"`
}

type fpWD struct {
	Properties fpProperties `json:"properties"`
}

type fpPhantomProps struct {
	Window []any `json:"window"`
}

type fpPhantom struct {
	Properties fpPhantomProps `json:"properties"`
}

type fpAutomation struct {
	WD      fpWD      `json:"wd"`
	Phantom fpPhantom `json:"phantom"`
}

type fpStealth struct {
	T1  int  `json:"t1"`
	T2  int  `json:"t2"`
	I   int  `json:"i"`
	Mte int  `json:"mte"`
	Mtd bool `json:"mtd"`
}

type fpCrypto struct {
	Crypto          int  `json:"crypto"`
	Subtle          int  `json:"subtle"`
	Encrypt         bool `json:"encrypt"`
	Decrypt         bool `json:"decrypt"`
	WrapKey         bool `json:"wrapKey"`
	UnwrapKey       bool `json:"unwrapKey"`
	Sign            bool `json:"sign"`
	Verify          bool `json:"verify"`
	Digest          bool `json:"digest"`
	DeriveBits      bool `json:"deriveBits"`
	DeriveKey       bool `json:"deriveKey"`
	GetRandomValues bool `json:"getRandomValues"`
	RandomUUID      bool `json:"randomUUID"`
}

type fpCanvas struct {
	Hash          int64 `json:"hash"`
	EmailHash     any   `json:"emailHash"`
	HistogramBins []int `json:"histogramBins"`
}

type fpBE struct {
	Si bool `json:"si"`
}

type fingerprint struct {
	Metrics         fpMetrics      `json:"metrics"`
	Start           int64          `json:"start"`
	FlashVersion    any            `json:"flashVersion"`
	Plugins         []fpPlugin     `json:"plugins"`
	DupedPlugins    string         `json:"dupedPlugins"`
	ScreenInfo      string         `json:"screenInfo"`
	Referrer        string         `json:"referrer"`
	UserAgent       string         `json:"userAgent"`
	Location        string         `json:"location"`
	WebDriver       bool           `json:"webDriver"`
	Capabilities    fpCapabilities `json:"capabilities"`
	GPU             fpGPU          `json:"gpu"`
	Dnt             any            `json:"dnt"`
	Math            fpMath         `json:"math"`
	Automation      fpAutomation   `json:"automation"`
	Stealth         fpStealth      `json:"stealth"`
	Crypto          fpCrypto       `json:"crypto"`
	Canvas          fpCanvas       `json:"canvas"`
	FormDetected    bool           `json:"formDetected"`
	NumForms        int            `json:"numForms"`
	NumFormElements int            `json:"numFormElements"`
	Be              fpBE           `json:"be"`
	End             int64          `json:"end"`
	Errors          []any          `json:"errors"`
	Version         string         `json:"version"`
	ID              string         `json:"id"`
}

var gpuExtensions = strings.Split(
	"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_astc;WEBGL_compressed_texture_etc;WEBGL_compressed_texture_etc1;WEBGL_compressed_texture_pvrtc;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode",
	";",
)

var pluginList = []fpPlugin{
	{Name: "PDF Viewer", Str: "PDF Viewer "},
	{Name: "Chrome PDF Viewer", Str: "Chrome PDF Viewer "},
	{Name: "Chromium PDF Viewer", Str: "Chromium PDF Viewer "},
	{Name: "Microsoft Edge PDF Viewer", Str: "Microsoft Edge PDF Viewer "},
	{Name: "WebKit built-in PDF", Str: "WebKit built-in PDF "},
}

func buildFingerprint(userAgent string) fingerprint {
	start := time.Now().UnixMilli()
	histogram := make([]int, 256)
	for i := range histogram {
		histogram[i] = rand.IntN(40)
	}
	return fingerprint{
		Metrics: fpMetrics{
			Fp2:          1,
			Browser:      0,
			Capabilities: 1,
			Gpu:          7,
			Dnt:          0,
			Math:         0,
			Screen:       0,
			Navigator:    0,
			Auto:         1,
			Stealth:      0,
			Subtle:       0,
			Canvas:       5,
			Formdetector: 1,
			Be:           0,
		},
		Start:        start,
		FlashVersion: nil,
		Plugins:      pluginList,
		DupedPlugins: "PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge PDF Viewer WebKit built-in PDF ||1920-1080-1032-24-*-*-*",
		ScreenInfo:   "1920-1080-1032-24-*-*-*",
		Referrer:     "",
		UserAgent:    userAgent,
		Location:     "",
		WebDriver:    false,
		Capabilities: fpCapabilities{
			CSS: fpCSS{
				TextShadow: 1, WebkitTextStroke: 1, BoxShadow: 1,
				BorderRadius: 1, BorderImage: 1, Opacity: 1,
				Transform: 1, Transition: 1,
			},
			JS: fpJS{
				Audio: true, Geolocation: rand.IntN(2) == 1,
				LocalStorage: "supported", Touch: false, Video: true,
				WebWorker: rand.IntN(2) == 1,
			},
			Elapsed: 1,
		},
		GPU: fpGPU{
			Vendor:     "Google Inc. (Apple)",
			Model:      "ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)",
			Extensions: gpuExtensions,
		},
		Dnt: nil,
		Math: fpMath{
			Tan: "-1.4214488238747245",
			Sin: "0.8178819121159085",
			Cos: "-0.5753861119575491",
		},
		Automation: fpAutomation{
			WD:      fpWD{Properties: fpProperties{Document: []any{}, Window: []any{}, Navigator: []any{}}},
			Phantom: fpPhantom{Properties: fpPhantomProps{Window: []any{}}},
		},
		Stealth: fpStealth{T1: 0, T2: 0, I: 1, Mte: 0, Mtd: false},
		Crypto: fpCrypto{
			Crypto: 1, Subtle: 1,
			Encrypt: true, Decrypt: true, WrapKey: true, UnwrapKey: true,
			Sign: true, Verify: true, Digest: true,
			DeriveBits: true, DeriveKey: true,
			GetRandomValues: true, RandomUUID: true,
		},
		Canvas: fpCanvas{
			Hash:          int64(rand.IntN(735192295-645172295)) + 645172295,
			EmailHash:     nil,
			HistogramBins: histogram,
		},
		FormDetected:    false,
		NumForms:        0,
		NumFormElements: 0,
		Be:              fpBE{Si: false},
		End:             start + int64(1+rand.IntN(5)),
		Errors:          []any{},
		Version:         "2.4.0",
		ID:              uuid.NewString(),
	}
}

type encodedPayload struct {
	Checksum  string
	Encoded   string
	Encrypted string
}

func buildPayload(userAgent string) (encodedPayload, error) {
	fp := buildFingerprint(userAgent)
	raw, err := json.Marshal(fp)
	if err != nil {
		return encodedPayload{}, err
	}
	payloadStr := string(raw)
	checksum := encodeNumber(calculateCRC(payloadStr))
	encoded := checksum + "#" + payloadStr
	encrypted, err := encryptPayload(encoded)
	if err != nil {
		return encodedPayload{}, err
	}
	return encodedPayload{
		Checksum:  checksum,
		Encoded:   encoded,
		Encrypted: encrypted,
	}, nil
}
