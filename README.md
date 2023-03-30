#### Sign-In

```
POST /api/authentication/sign-in HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 50

{
  "username": "user",
  "password": "user"
} 
```

#### Sign-Up

```
POST /api/authentication/sign-up HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 72

{
  "username": "user1",
  "password": "user1",
  "name": "user1"
} 
```

#### Make-admin

```
PUT /api/internal/make-admin/user HTTP/1.1
Host: localhost:8080
Authorization: Bearer InternalApiKey1234!
```

#### Save-book

```
POST /api/book HTTP/1.1
Host: localhost:8080
Authorization: Bearer ...admin
Content-Type: application/json
Content-Length: 117

{
  "title": "test book 2",
  "description": "test description 2",
  "author": "test author 2",
  "price": 100
}
```


#### Delete-book

```
DELETE /api/book/2 HTTP/1.1
Host: localhost:8080
Authorization: Bearer ...admin
```

#### Get-book

```
GET /api/book HTTP/1.1
Host: localhost:8080
```

#### Create-purchase-history

```
POST /api/purchase-history HTTP/1.1
Host: localhost:8080
Authorization: Bearer ...admin or user
Content-Type: application/json
Content-Length: 51

{
  "userId": 3,
  "bookId": 1,
  "price": 10
}
```

#### Get-purchase-history

```
GET /api/purchase-history HTTP/1.1
Host: localhost:8080
Authorization: Bearer ...admin or user
```


