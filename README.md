# CS 493 - REST API in Go

This is a JSON-based REST API, written in Go, that can be used to create a user account and store data on two related entities: pizzas and toppings. New users are prompted to authenticate via Google OAuth, which generates a JWT that can be used to authenticate subsequent JSON requests.

This was the final project for Oregon State's **CS 493 - Cloud Application Development**. The API was previously hosted on Google App Engine, a Google Cloud Platform product. 

## Usage

Visitors to the root URL of the hosted API are presented with an HTML page, containing a link to authenticate with Google's OAuth service. Once users authenticate, they are presented with a JWT that must be included in the header of any subsequent requests. 

Once authenticated, users can take all standard CRUD actions on pizzas or toppings they create, including associating/unassociating one or more toppings with a given pizza. Extensive error handling is also included. For comprehensive documentation of all endpoints, see the file [lambethw_project.pdf](lambethw_project.pdf). 

## Examples

Requesting a list of users by ID: 
```
request:
GET /users
Accept: application/json

response:
200 OK
{
"id": "118077088807767242950",
"id": "432081239012309123103"
}
```

Creating a pizza: 
```
request:
POST /pizzas
Accept: application/json
Authorization: Bearer JWT_TOKEN_HERE
{
"name": "My New 'Za",
"size": 21,
"style": "Sicilian"
}


response:
201 CREATED
{
"id": 5,
"owner": "118077088807767242950",
"name": "My New 'Za",
"size": 21,
"style": "Sicilian",
"topping": "",
"self": "https://APP_URL/pizzas/5"
}
```
