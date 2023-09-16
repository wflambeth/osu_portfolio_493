package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/logging"
	"github.com/dchest/uniuri"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/iterator"
)

var logger *log.Logger
var client *firestore.Client
var topping_count int
var pizza_count int

var APP_URL = "final-493-wfl.wl.r.appspot.com"
var CLIENT_ID = "PLACEHOLDER_FAKE_ID.apps.googleusercontent.com"
var CLIENT_SECRET = "PLACEHOLDER_FAKE_SECRET"

func main() {
	ctx := context.Background()
	project_id := "final-493-wfl"
	logname := "final-493-manual-logs"

	// create db client
	client = createDBClient(ctx)
	defer client.Close()

	// initialize logger
	log_client, err := logging.NewClient(ctx, project_id)
	if err != nil {
		log.Fatalf("Failed to create logging client: %v", err)
	}
	defer log_client.Close()
	logger = log_client.Logger(logname).StandardLogger(logging.Info)
	logger.Print("Logger created")

	// initialize db counters
	topping_count = getCollectionLength("toppings")
	pizza_count = getCollectionLength("pizzas")

	// initialize router and routes
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Route("/", func(r chi.Router) {
		r.Get("/", renderHello)
		r.Get("/auth", receiveAuth)
		r.Get("/init_auth", requestAuth)
		r.Get("/users", getAllUsers)

		r.Route("/toppings", func(r chi.Router) {
			r.Post("/", createTopping)
			r.Get("/", getAllToppings)
			r.Route("/{topping_id}", func(r chi.Router) {
				r.Get("/", getTopping)
				r.Put("/", updateTopping)
				r.Patch("/", updateTopping)
				r.Delete("/", deleteTopping)
			})
		})

		r.Route("/pizzas", func(r chi.Router) {
			r.Post("/", createPizza)
			r.Get("/", getAllPizzas)
			r.Route("/{pizza_id}", func(r chi.Router) {
				r.Get("/", getPizza)
				r.Put("/", updatePizza)
				r.Patch("/", updatePizza)
				r.Delete("/", deletePizza)

				r.Route("/topping/{topping_id}", func(r chi.Router) {
					r.Put("/", addToppingToZa)
					r.Delete("/", removeToppingFromZa)
				})
			})
		})
	})

	// listen and serve
	port := "8080"
	if err := http.ListenAndServe(":"+port, r); err != nil {
		logger.Fatalf("Error while serving requests: %v", err)
	}
}

// Retrieves the size of a given collection in the DB
func getCollectionLength(key string) int {
	ctx := context.Background()
	iter := client.Collection(key).Snapshots(ctx)
	defer iter.Stop()

	col, err := iter.Next()
	if err == iterator.Done {
		return 0
	} else if err != nil {
		logger.Fatalf("Error retrieving collection length on startup: %v", err)
	}
	return (col.Size)
}

// Create Firestore client for database storage
func createDBClient(ctx context.Context) *firestore.Client {
	projectID := firestore.DetectProjectID

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Error creating client. | %s", err)
	}
	return client
}

// Render welcome template with link to request OAuth verification
func renderHello(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "hello.html")
}

// Request OAuth verification via redirect to Google
func requestAuth(w http.ResponseWriter, r *http.Request) {
	state := uniuri.New()

	url := makeAuthRedirect(state)

	logger.Printf("Requesting redirect with url:  %s", url)
	http.Redirect(w, r, url, http.StatusFound)
}

// Build query string for Google OAuth redirect
func makeAuthRedirect(state string) string {
	s := "https://accounts.google.com/o/oauth2/v2/auth?" +
		"scope=openid%20profile%20email&" +
		"access_type=offline&" +
		"include_granted_scopes=true&" +
		"response_type=code&" +
		"state=" + state + "&" +
		"redirect_uri=https%3A//" + APP_URL + "/auth&" +
		"client_id=" + CLIENT_ID
	return s
}

type TokenResponse struct {
	Access_Token  string `json:"access_token"`
	Expires       int    `json:"expires_in"`
	Type          string `json:"token_type"`
	Scope         string `json:"scope"`
	Refresh_Token string `json:"refresh_token"`
	ID_Token      string `json:"id_token"`
}

type TokenValidatorResponse struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Hd            string `json:"hd"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	AtHash        string `json:"at_hash"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           string `json:"iat"`
	Exp           string `json:"exp"`
	Alg           string `json:"alg"`
	Kid           string `json:"kid"`
	Typ           string `json:"typ"`
}

type JWTDisplay struct {
	JWT string `json:"jwt"`
	ID  string `json:"id"`
}

// Handle response from successful OAuth, create/display JSON token
func receiveAuth(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// log successful Auth code delivery
	logger.Printf("Auth response received: %s", r.URL.RawQuery)

	auth_code := r.FormValue("code")
	logger.Printf("Auth code received: %s", auth_code)

	// build body of POST request for token
	body := "code=" + auth_code +
		"&client_id=" + CLIENT_ID +
		"&client_secret=" + CLIENT_SECRET +
		"&redirect_uri=" + "https%3A//" + APP_URL + "/auth" +
		"&grant_type=authorization_code"

	token_req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(body))
	if err != nil {
		logger.Fatalf("Error creating token request: %v", err)
	}
	token_req.Header.Set("content-type", "application/x-www-form-urlencoded")

	// create custom client with timeout value (default client has none, may hang indefinitely)
	http_client := &http.Client{
		Timeout: time.Second * 10,
	}

	// execute token request
	post_res, err := http_client.Do(token_req)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Print("Token response received!")
	logger.Print("Token response code: " + post_res.Status)

	// decode response into struct
	var res_data TokenResponse
	d := json.NewDecoder(post_res.Body)
	err = d.Decode(&res_data)
	if err != nil {
		http.Error(w, "Error decoding JSON", 500)
		logger.Printf("Struct Decoding error: %v", err)
		return
	}
	logger.Printf("Token Request Response: %v", res_data)

	// extract raw token
	token, _ := jwt.ParseWithClaims(res_data.ID_Token, jwt.RegisteredClaims{}, nil)

	// validate and extract sub value
	sub := validateAndGetSub(token.Raw)

	// Check if the user has an existing account; if not, create one
	user, err := client.Collection("users").Where("id", "==", sub).Documents(ctx).GetAll()
	if err != nil {
		logger.Fatalf("Error checking for existing sub user: %v", err)
	}
	if len(user) == 0 {
		_, _, err = client.Collection("users").Add(ctx, map[string]interface{}{
			"id": sub,
		})
		if err != nil {
			logger.Fatalf("Error saving new user: %v", err)
		}
	}

	// create and load data structure for template/ID display
	var tmpl_data JWTDisplay
	tmpl_data.JWT = token.Raw
	tmpl_data.ID = sub
	logger.Print("Template data loaded: ")
	logger.Print(tmpl_data)

	// execute template display
	tp, err := template.New("show_jwt.tmpl").ParseFiles("show_jwt.tmpl")
	if err != nil {
		logger.Fatalf("Error parsing JWT display template: %v", err)
	}
	err = tp.Execute(w, tmpl_data)
	if err != nil {
		logger.Fatalf("Error executing JWT display template: %v", err)
	}
}

// Extract JWT string value from an HTTP request
func extractJWTVal(r *http.Request) string {
	auth_header := r.Header.Get("Authorization")
	token_val := strings.Split(auth_header, "Bearer")
	if len(token_val) != 2 {
		return ""
	}
	auth_header = strings.TrimSpace(token_val[1])
	return auth_header
}

// Check that JWT value provided is valid, and return 'sub' value if so
func validateAndGetSub(token string) string {
	if token == "" {
		return ""
	}

	// create custom client with timeout value (default client has none, may hang indefinitely)
	http_client := &http.Client{
		Timeout: time.Second * 10,
	}

	url := "https://oauth2.googleapis.com/tokeninfo?id_token=" + token
	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http_client.Do(req)

	if res.StatusCode > 399 {
		return ""
	}

	var t_res TokenValidatorResponse
	d := json.NewDecoder(res.Body)

	err := d.Decode(&t_res)
	if err != nil {
		logger.Printf("Error validating token response: %v", err)
		return ""
	}

	logger.Printf("Token Request Response: %v", t_res)
	return t_res.Sub
}

// Return all users stored in DB
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	iter := client.Collection("users").Documents(ctx)

	var users []map[string]interface{}
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			logger.Fatalf("Error extracting user data: %v", err)
			jsonResponder(w, "Error extracting user data", 500)
			return
		}
		users = append(users, doc.Data())
	}
	// set array to empty slice if empty, so as to return []
	if len(users) == 0 {
		users = make([]map[string]interface{}, 0)
	}
	res, err := json.Marshal(users)
	if err != nil {
		logger.Fatalf("Error marshalling user JSON: %v", err)
		jsonResponder(w, "Error marshalling user JSON", 500)
		return
	}

	jsonResponder(w, res, 200)
}

// Shortcut function for creating JSON HTTP responses
func jsonResponder(w http.ResponseWriter, content interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(content)
}

// Validates presence of JSON Accept header in request
// (needed for all except DELETE requests)
func reqHeadersAcceptJson(r *http.Request) bool {
	acpt_hdr := r.Header.Get("Accept")
	return ((acpt_hdr == "application/json") || (acpt_hdr == "*/*"))
}

type Topping struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Tastiness   *int   `json:"tastiness"` // pointers allow for distinguishing between zero and missing values
	Spiciness   *int   `json:"spiciness"`
	Traditional *bool  `json:"traditional"`
	Self        string `json:"self"`
}

// Create new pizza topping
func createTopping(w http.ResponseWriter, r *http.Request) {
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	ctx := context.Background()

	// extract topping data
	var t Topping
	data := json.NewDecoder(r.Body)
	err := data.Decode(&t)
	if err != nil {
		jsonResponder(w, "Error decoding request data", 500)
		return
	}
	// add ID and "self" value
	topping_count++
	t.ID = topping_count
	t.Self = APP_URL + "/toppings/" + strconv.Itoa(t.ID)

	// save in DB
	_, _, err = client.Collection("toppings").Add(ctx, map[string]interface{}{
		"id":          t.ID,
		"name":        t.Name,
		"tastiness":   t.Tastiness,
		"spiciness":   t.Spiciness,
		"traditional": t.Traditional,
		"self":        t.Self,
	})
	if err != nil {
		logger.Printf("Error saving topping: %v", err)
		jsonResponder(w, err, 500)
		return
	}

	// return success
	jsonResponder(w, t, 201)
}

// Return paginated list of all pizza toppings
func getAllToppings(w http.ResponseWriter, r *http.Request) {
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	ctx := context.Background()

	iter := client.Collection("toppings").OrderBy("id", firestore.Asc).Documents(ctx)

	// pull offset from query string
	offset_str := r.FormValue("offset")
	offset, err := strconv.Atoi(offset_str)
	// if offset is invalid or missing, default to 0
	if err != nil {
		offset = 0
	}

	next_offset := strconv.Itoa((offset + 5)) // For use in return JSON, if needed
	page_count := 0
	total_count := 0
	is_last := false

	// iterate through toppings
	var toppings []map[string]interface{}
	for {
		doc, err := iter.Next()
		// if end of results, break
		if err == iterator.Done {
			is_last = true
			break
			// if page limit already hit, increment count and carry on iterating
		} else if page_count == 5 {
			total_count++
			continue
		} else if err != nil {
			logger.Fatalf("Error extracting user data: %v", err)
		}
		// if we have yet to hit offset point, don't append
		if offset > 0 {
			offset--
		} else if page_count < 5 {
			// append to output struct
			toppings = append(toppings, doc.Data())
			page_count++
		}
		// Gets full count of items; continues iterating even after output is populated
		total_count++
	}

	// create "next" link
	var next_link string
	if !(is_last) {
		next_link = APP_URL + "/toppings/?offset=" + next_offset
	} else {
		next_link = "n/a"
	}

	// set array to empty slice if empty, so as to return []
	if len(toppings) == 0 {
		toppings = make([]map[string]interface{}, 0)
	}

	toppings = append(toppings, map[string]interface{}{"next_link": next_link})
	toppings = append(toppings, map[string]interface{}{"total_count": total_count})

	res, err := json.Marshal(toppings)
	if err != nil {
		logger.Fatalf("Error marshalling user JSON: %v", err)
		jsonResponder(w, "Error marshalling user JSON", 500)
		return
	}
	jsonResponder(w, res, 200)
}

// Retrieve details of specific pizza topping
func getTopping(w http.ResponseWriter, r *http.Request) {
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	ctx := context.Background()

	// pull and validate topping ID
	str_id := chi.URLParam(r, "topping_id")
	top_id, err := strconv.Atoi(str_id)
	if err != nil {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}

	// pull topping from collection and populate struct
	iter, err := client.Collection("toppings").Where("id", "==", top_id).Documents(ctx).GetAll()
	if err != nil || len(iter) == 0 {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}
	snap := iter[0]
	var t Topping
	if err := snap.DataTo(&t); err != nil {
		logger.Fatalf("Error unpacking topping data: %v", err)
	}

	// respond with struct in JSON format
	jsonResponder(w, t, 200)
}

// Update specific pizza topping (either PATCH or PUT)
func updateTopping(w http.ResponseWriter, r *http.Request) {
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	ctx := context.Background()

	// pull and validate topping ID
	str_id := chi.URLParam(r, "topping_id")
	top_id, err := strconv.Atoi(str_id)
	if err != nil {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}

	// extract topping data from request body
	var t Topping
	d := json.NewDecoder(r.Body)
	err = d.Decode(&t)
	if err != nil {
		jsonResponder(w, "Error: Invalid data provided", 400)
		return
	}

	// pull topping from DB for comparison
	iter, err := client.Collection("toppings").Where("id", "==", top_id).Documents(ctx).GetAll()
	if err != nil || len(iter) == 0 {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}
	t_db := iter[0]
	t_data := t_db.Data()

	// combine old data with what is provided in request body
	if t.Name == "" {
		t.Name = t_data["name"].(string)
	}
	if t.Spiciness == nil {
		spice_int := int(t_data["spiciness"].(int64))
		t.Spiciness = &spice_int
	}
	if t.Tastiness == nil {
		taste_int := int(t_data["tastiness"].(int64))
		t.Tastiness = &taste_int
	}
	if t.Traditional == nil {
		trad_bool := t_data["traditional"].(bool)
		t.Traditional = &trad_bool
	}

	// write updated values back to DB
	t_db.Ref.Update(ctx, []firestore.Update{
		{Path: "name", Value: t.Name},
		{Path: "spiciness", Value: t.Spiciness},
		{Path: "tastiness", Value: t.Tastiness},
		{Path: "traditional", Value: t.Traditional},
	})

	// pull updated object and return
	snap, err := t_db.Ref.Get(ctx)
	if err != nil {
		logger.Fatalf("Error pulling updated DB item: %v", err)
		w.WriteHeader(500)
		return
	}
	if err := snap.DataTo(&t); err != nil {
		logger.Fatalf("Error pulling updated DB values: %v", err)
		w.WriteHeader(500)
		return
	}
	jsonResponder(w, t, 201)

}

// Remove given pizza topping from DB
func deleteTopping(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// pull and validate topping ID
	str_id := chi.URLParam(r, "topping_id")
	top_id, err := strconv.Atoi(str_id)
	if err != nil {
		jsonResponder(w, "Error: Invalid Topping ID", 400)
		return
	}

	// locate topping in DB
	iter := client.Collection("toppings").Where("id", "==", top_id).Limit(1).Documents(ctx)
	t, err := iter.Next()
	if err != nil {
		jsonResponder(w, "Error: No boat exists with that ID", 404)
		return
	}

	// delet it
	_, err = t.Ref.Delete(ctx)
	if err != nil {
		logger.Printf("Error deleting topping: %v", err)
		jsonResponder(w, "Error deleting topping", 500)
		return
	}

	// locate any pizzas with this topping
	iter = client.Collection("pizzas").Where("topping_id", "==", top_id).Documents(ctx)
	// step through these 'zas and set toppings back to null
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		doc.Ref.Update(ctx, []firestore.Update{
			{Path: "topping", Value: ""},
			{Path: "topping_id", Value: 0},
		})
	}

	// :)
	w.WriteHeader(http.StatusNoContent)
}

type Pizza struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Style     string `json:"style"`
	Size      int    `json:"size"` // non-pointer; rejects 0 values, as intended
	Owner     string `json:"owner"`
	Topping   string `json:"topping"`
	ToppingID int    `json:"-"`
	Self      string `json:"self"`
}

// Create new pizza
func createPizza(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}
	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// Confirm user with Sub value exists in DB
	iter := client.Collection("users").Where("id", "==", sub).Limit(1).Documents(ctx)
	_, err := iter.Next()
	if err != nil {
		jsonResponder(w, "Error: JWT provided is not for a registered user", 403)
		return
	}

	// extract pizza values from request JSON and populate struct
	var p Pizza
	data := json.NewDecoder(r.Body)
	err = data.Decode(&p)
	if err != nil {
		jsonResponder(w, "Invalid data provided", 400)
		return
	}

	// Populate autogenerated values
	pizza_count++
	p.ID = pizza_count
	p.Self = APP_URL + "/pizzas/" + strconv.Itoa(p.ID)
	p.Owner = sub

	// save pizza in DB
	_, _, err = client.Collection("pizzas").Add(ctx, map[string]interface{}{
		"id":         p.ID,
		"name":       p.Name,
		"style":      p.Style,
		"size":       p.Size,
		"owner":      p.Owner,
		"topping":    "",
		"topping_id": 0,
		"self":       p.Self,
	})
	if err != nil {
		logger.Printf("Error saving pizza: %v", err)
		jsonResponder(w, err, 500)
		return
	}

	// return success
	jsonResponder(w, p, 201)
}

// Get paginated list of all pizzas
func getAllPizzas(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Validate that "Accept: application/json" included in headers
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// Confirm user with Sub value exists in DB
	iter := client.Collection("users").Where("id", "==", sub).Limit(1).Documents(ctx)
	_, err := iter.Next()
	if err != nil {
		jsonResponder(w, "Error: JWT provided is not for a registered user", 403)
		return
	}

	// Get all pizzas owned by this user
	iter = client.Collection("pizzas").Where("owner", "==", sub).Documents(ctx)

	// pull offset from query string
	offset_str := r.FormValue("offset")
	offset, err := strconv.Atoi(offset_str)
	// if offset is invalid or missing, default to 0
	if err != nil {
		offset = 0
	}

	next_offset := strconv.Itoa((offset + 5)) // For use in return JSON, if needed
	page_count := 0
	total_count := 0
	is_last := false

	// iterate through pizzas
	var pizzas []map[string]interface{}
	for {
		doc, err := iter.Next()
		// if end of results, break
		if err == iterator.Done {
			is_last = true
			break
			// if page limit already hit, increment count and carry on iterating
		} else if page_count == 5 {
			total_count++
			continue
		} else if err != nil {
			logger.Fatalf("Error extracting user data: %v", err)
		}
		// if we have yet to hit offset point, don't append
		if offset > 0 {
			offset--
		} else if page_count < 5 {
			// append to output struct
			pizzas = append(pizzas, doc.Data())
			page_count++
		}
		// Gets full count of items; continues iterating even after output is populated
		total_count++
	}

	// create "next" link
	var next_link string
	if !(is_last) {
		next_link = APP_URL + "/pizzas/?offset=" + next_offset
	} else {
		next_link = "n/a"
	}

	// set array to empty slice if empty, so as to return []
	if len(pizzas) == 0 {
		pizzas = make([]map[string]interface{}, 0)
	}

	pizzas = append(pizzas, map[string]interface{}{"next_link": next_link})
	pizzas = append(pizzas, map[string]interface{}{"total_count": total_count})

	res, err := json.Marshal(pizzas)
	if err != nil {
		logger.Fatalf("Error marshalling user JSON: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)
}

// Get details of single pizza
func getPizza(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Validate that "Accept: application/json" included in headers
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}
	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// pull and validate pizza ID
	str_id := chi.URLParam(r, "pizza_id")
	piz_id, err := strconv.Atoi(str_id)
	logger.Printf("Pizza ID extracted: %d", piz_id)
	if err != nil {
		jsonResponder(w, "Error: Pizza ID Not Found", 404)
		return
	}

	// pull pizza from collection and populate struct
	iter, err := client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting pizza: %v", err)
		jsonResponder(w, "Error extracting pizza", 500)
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}
	snap := iter[0]
	var p Pizza
	if err := snap.DataTo(&p); err != nil {
		logger.Fatalf("Error unpacking pizza data: %v", err)
		jsonResponder(w, "Error unpacking pizza data", 500)
		return
	}

	// if this user doesn't own pizza, return 403
	if p.Owner != sub {
		jsonResponder(w, "Error: Not authorized to access this pizza", 403)
		return
	}

	// display pizza to user
	jsonResponder(w, p, 200)
}

// Update a given pizza (either PATCH or PUT)
func updatePizza(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Validate that "Accept: application/json" included in headers
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}
	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// pull and validate pizza ID
	str_id := chi.URLParam(r, "pizza_id")
	piz_id, err := strconv.Atoi(str_id)
	logger.Printf("Pizza ID extracted: %d", piz_id)
	if err != nil {
		jsonResponder(w, "Error: Invalid Pizza ID", 400)
		return
	}

	// pull pizza from collection and populate struct
	iter, err := client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting pizza: %v", err)
		jsonResponder(w, "Error extracting pizza", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}
	p_db := iter[0]
	p_data := p_db.Data()

	// if this user doesn't own pizza, return 403
	if p_data["owner"].(string) != sub {
		jsonResponder(w, "Error: Not authorized to access this pizza", 403)
		return
	}

	// pull new pizza data from request body into struct
	var np Pizza
	d := json.NewDecoder(r.Body)
	err = d.Decode(&np)
	if err != nil {
		logger.Fatalf("Error decoding update data: %v", err)
		w.WriteHeader(500)
		return
	}

	// update new data with old values for any empty fields
	if np.Name == "" {
		np.Name = p_data["name"].(string)
	}
	if np.Size == 0 {
		np.Size = int(p_data["size"].(int64))
	}
	if np.Style == "" {
		np.Style = p_data["style"].(string)
	}

	// save new values back into DB
	p_db.Ref.Update(ctx, []firestore.Update{
		{Path: "name", Value: np.Name},
		{Path: "size", Value: np.Size},
		{Path: "style", Value: np.Style},
	})

	// pull updated object and return
	snap, err := p_db.Ref.Get(ctx)
	if err != nil {
		logger.Printf("Error pulling updated DB item: %v", err)
		jsonResponder(w, "Error pulling updated DB item", 500)
		return
	}
	if err := snap.DataTo(&np); err != nil {
		logger.Printf("Error pulling updated DB values: %v", err)
		jsonResponder(w, "Error pulling updated DB values", 500)
		return
	}
	jsonResponder(w, np, 201)

}

// Delete a given pizza
func deletePizza(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// pull and validate pizza ID
	str_id := chi.URLParam(r, "pizza_id")
	piz_id, err := strconv.Atoi(str_id)
	logger.Printf("Pizza ID extracted: %d", piz_id)
	if err != nil {
		jsonResponder(w, "Error: Invalid Pizza ID", 400)
		return
	}

	// check if pizza exists
	iter, err := client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting pizza: %v", err)
		jsonResponder(w, "Error extracting pizza", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}

	// check if user owns the pizza
	iter, err = client.Collection("pizzas").Where("id", "==", piz_id).Where("owner", "==", sub).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error validating pizza ownership: %v", err)
		jsonResponder(w, "Error validating pizza ownership", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Not authorized to access this pizza", 403)
		return
	}

	// kill the pizza
	p := iter[0]
	_, err = p.Ref.Delete(ctx)
	if err != nil {
		logger.Printf("Error deleting pizza: %v", err)
		jsonResponder(w, "Error deleting pizza", 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Create relationship between pizza and topping
func addToppingToZa(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Validate that "Accept: application/json" included in headers
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// pull and validate pizza ID
	str_id := chi.URLParam(r, "pizza_id")
	piz_id, err := strconv.Atoi(str_id)
	logger.Printf("Pizza ID extracted: %d", piz_id)
	if err != nil {
		jsonResponder(w, "Error: Invalid Pizza ID", 400)
		return
	}

	// check if pizza exists
	iter, err := client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting pizza: %v", err)
		jsonResponder(w, "Error extracting pizza", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}

	// extract pizza data
	p := iter[0]
	pd := p.Data()
	// confirm user owns pizza
	if pd["owner"].(string) != sub {
		jsonResponder(w, "Error: Not authorized to access this pizza", 403)
		return
	}
	// confirm no topping
	if int(pd["topping_id"].(int64)) != 0 {
		jsonResponder(w, "Error: This pizza already has a topping. (Sorry, one per pie!)", 403)
		return
	}

	// pull and validate topping ID
	tp_str_id := chi.URLParam(r, "topping_id")
	top_id, err := strconv.Atoi(tp_str_id)
	if err != nil {
		jsonResponder(w, "Error: Invalid Topping ID", 400)
		return
	}

	// check if topping exists
	iter, err = client.Collection("toppings").Where("id", "==", top_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting topping: %v", err)
		jsonResponder(w, "Error extracting topping", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}

	// extract topping data
	t_snap := iter[0]
	var t Topping
	if err := t_snap.DataTo(&t); err != nil {
		logger.Printf("Error extracting topping values: %v", err)
		jsonResponder(w, "Error extracting topping values", 500)
		return
	}

	// add topping details to pizza DB and save
	p.Ref.Update(ctx, []firestore.Update{
		{Path: "topping", Value: t.Name},
		{Path: "topping_id", Value: t.ID},
	})

	// pull updated 'za and return
	iter, err = client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error pulling updated pizza item: %v", err)
		jsonResponder(w, "Error pulling updated pizza item", 500)
		return
	}
	snap := iter[0]
	var pz Pizza
	if err := snap.DataTo(&pz); err != nil {
		logger.Printf("Error pulling updated pizza values: %v", err)
		jsonResponder(w, "Error pulling updated pizza values", 500)
		return
	}

	jsonResponder(w, pz, 201)
}

// Delete relationship between pizza and topping
func removeToppingFromZa(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Validate that "Accept: application/json" included in headers
	if !(reqHeadersAcceptJson(r)) {
		jsonResponder(w, "Error: Accept header must be configured for application/json", 406)
		return
	}

	// get valid JWT and "Sub" value
	jwt := extractJWTVal(r)
	sub := validateAndGetSub(jwt)
	if sub == "" {
		jsonResponder(w, "Error: must provide a valid JWT in header", 401)
		return
	}

	// pull and validate pizza ID
	str_id := chi.URLParam(r, "pizza_id")
	piz_id, err := strconv.Atoi(str_id)
	logger.Printf("Pizza ID extracted: %d", piz_id)
	if err != nil {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}

	// pull and validate topping ID
	tp_str_id := chi.URLParam(r, "topping_id")
	top_id, err := strconv.Atoi(tp_str_id)
	if err != nil {
		jsonResponder(w, "Error: Topping not found", 404)
		return
	}

	// check if pizza exists
	iter, err := client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error extracting pizza: %v", err)
		jsonResponder(w, "Error extracting pizza", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Pizza not found", 404)
		return
	}

	// check if user owns the pizza
	iter, err = client.Collection("pizzas").Where("id", "==", piz_id).Where("owner", "==", sub).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error validating pizza ownership: %v", err)
		jsonResponder(w, "Error validating pizza ownership", 500)
		return
	} else if len(iter) == 0 {
		jsonResponder(w, "Error: Not authorized to access this pizza", 403)
		return
	}

	// extract pizza data
	p := iter[0]
	pd := p.Data()

	// confirm pizza has topping currently
	if int(pd["topping_id"].(int64)) != top_id {
		jsonResponder(w, "Error: Topping not present on this pizza", 404)
		return
	}

	// remove topping
	p.Ref.Update(ctx, []firestore.Update{
		{Path: "topping", Value: ""},
		{Path: "topping_id", Value: 0},
	})

	// pull updated 'za and return
	iter, err = client.Collection("pizzas").Where("id", "==", piz_id).Documents(ctx).GetAll()
	if err != nil {
		logger.Printf("Error pulling updated pizza item: %v", err)
		jsonResponder(w, "Error pulling updated pizza item", 500)
		return
	}
	snap := iter[0]
	var pz Pizza
	if err := snap.DataTo(&pz); err != nil {
		logger.Printf("Error pulling updated pizza values: %v", err)
		jsonResponder(w, "Error pulling updated pizza values", 500)
		return
	}

	jsonResponder(w, pz, 201)
}
