# User Management API

This project is a FastAPI-based application for managing user accounts, providing features such as user registration, authentication, role-based access control, and HATEOAS navigation. The API supports asynchronous operations, pagination, and robust error handling to ensure optimal performance and usability. Working on this project has been a rewarding yet challenging experience, providing hands-on exposure to professional software development practices. One of the key takeaways is the importance of planning and modularity in software engineering. Breaking down the project into smaller, manageable components, though sadly I didn't take into consideration on how much a small portion is within a time frame nor think of time line that manage the project. The work I have so far might not be enough to work on half of the features mentioned but this is what I believe it can do once I actually finish the whole thing before due time.  

## Features

### 1. User Registration and Authentication
- **Register New Users**: Users can sign up with a unique username, email, and password.
- **Login**: Authenticate users using OAuth2 Password Flow, generating JWT tokens for secure session management.

### 2. Role-Based Access Control
- Restrict access to specific endpoints based on user roles (e.g., `admin` and `user`).
- Middleware ensures only authorized users can access sensitive operations like managing other users.

### 3. CRUD Operations
- **Create**: Add new users with default or assigned roles.
- **Read**: Retrieve user details or a paginated list of users.
- **Update**: Modify user information, such as email or role.
- **Delete**: Remove users from the system.

### 4. Pagination
- API responses for listing users include pagination support with `limit` and `offset` parameters.
- Dynamic HATEOAS links enable seamless navigation through paginated results.

### 5. HATEOAS Support
- Hypermedia links included in API responses for easy discovery of related actions (e.g., self, update, delete).

### 6. Error Handling
- Comprehensive error messages and HTTP status codes ensure clear feedback for invalid requests.
- Example: `HTTP 404` for non-existent users, `HTTP 400` for invalid input.

### 7. Asynchronous Design
- Leverages FastAPI's asynchronous capabilities for non-blocking I/O operations with the database.
