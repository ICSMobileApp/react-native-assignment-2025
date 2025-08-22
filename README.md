# BankingMockAPI

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher)
- [Docker](https://www.docker.com/) (optional, for containerized setup)

### Installation

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd BankingMockAPI
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

### Running the Server

#### With Node.js
```bash
node server.js
```
The server will start on [http://localhost:3001](http://localhost:3001) by default.

#### With Docker
```bash
docker build -t banking-mock-api .
docker run --name banking-mock-api -d -p 3001:3001 banking-mock-api
```

Same as mentioned aboe the api will be available at on [http://localhost:3001](http://localhost:3001)

Use following commands to stop or start the container:
```bash
docker container stop banking-mock-api
docker container start banking-mock-api
```


## API Endpoints

### Authentication

#### `POST /login`
Authenticate user and receive JWT and refresh token.
- **Body:**
  ```json
  {
    "username": "test@test.test",
    "password": "password@123"
  }
  ```
- **Response:**
  ```json
  {
    "token": "<JWT>",
    "refreshToken": "<refresh_token>"
  }
  ```

#### `POST /refresh-token`
Get a new JWT using a refresh token.
- **Body:**
  ```json
  {
    "refreshToken": "<refresh_token>"
  }
  ```
- **Response:**
  ```json
  {
    "token": "<new_JWT>",
    "refreshToken": "<new_refresh_token>"
  }
  ```


### Accounts

#### `GET /accounts`
Get all accounts for the authenticated user.
- **Headers:**
  - `Authorization: Bearer <JWT>`
- **Response:**
  ```json
  [
    {
      "id": 1,
      "user_id": 1,
      "name": "Checking",
      "balance": 1500.5
    },
    ...
  ]
  ```

### Cards

#### `GET /cards`
Get all cards for the authenticated user.
- **Headers:**
  - `Authorization: Bearer <JWT>`
- **Response:**
  ```json
  [
    {
      "id": 1,
      "user_id": 1,
      "number": "4111111111111111",
      "expiry": "12/26",
      "cvv": "123"
    },
    ...
  ]
  ```

### Transactions

#### `GET /transactions`
Get transactions for the authenticated user, with search, sort, and pagination.
- **Headers:**
  - `Authorization: Bearer <JWT>`
- **Query Parameters:**
  - `search` (optional): Search by description or type
  - `sort` (optional): Field to sort by (default: `date`)
  - `order` (optional): `asc` or `desc` (default: `desc`)
  - `page` (optional): Page number (default: `1`)
  - `limit` (optional): Items per page (default: `10`)
- **Response:**
  ```json
  [
    {
      "id": 1,
      "user_id": 1,
      "account_id": 1,
      "amount": -50.25,
      "type": "debit",
      "description": "Grocery Store",
      "date": "2024-06-01T10:00:00Z"
    },
    ...
  ]
  ```

## Default Test User
- **Username:** `test@test.test`
- **Password:** `password@123`

## Database
- The SQLite database is used.
- The database is reset and seeded with test data every time the server starts.