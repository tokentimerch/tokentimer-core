const { TestUtils, request, expect } = require("./test-server");

/**
 * Standardized server health check test
 */
const testServerHealth = async () => {
  const response = await request("http://localhost:4000").get("/").expect(200);

  expect(response.body).to.be.an("object");
};

/**
 * Standardized invalid login test
 */
const testInvalidLogin = async (
  email = "test@example.com",
  password = "wrongpassword",
) => {
  const response = await request("http://localhost:4000")
    .post("/auth/login")
    .send({
      email: email,
      password: password,
    })
    .expect(401);

  expect(response.body).to.have.property("error");
  expect(response.body.error).to.include("Invalid credentials");
};

/**
 * Standardized user registration test
 */
const testUserRegistration = async (
  email = null,
  password = "SecureTest123!@#",
  name = "Test User",
) => {
  const testEmail = email || TestUtils.generateTestEmail();

  const response = await request("http://localhost:4000")
    .post("/auth/register")
    .send({
      email: testEmail,
      password: password,
      name: name,
    })
    .expect(201);

  expect(response.body).to.have.property("user");
  expect(response.body.user).to.have.property("email", testEmail);

  return { response, testEmail };
};

/**
 * Standardized login test for test environment
 */
const testLoginInTestMode = async (email, password = "SecureTest123!@#") => {
  const response = await request("http://localhost:4000")
    .post("/auth/login")
    .send({
      email: email,
      password: password,
    })
    .expect(200);

  expect(response.body).to.have.property("message", "Login successful");
  expect(response.body).to.have.property("user");

  return response;
};

/**
 * Standardized email validation test
 */
const testEmailValidation = async (invalidEmails) => {
  for (const email of invalidEmails) {
    const response = await request("http://localhost:4000")
      .post("/auth/register")
      .send({
        email: email,
        password: "SecureTest123!@#",
        name: "Test User",
      })
      .expect(400);

    expect(response.body.error).to.include("valid email");
  }
};

/**
 * Standardized password validation test
 */
const testPasswordValidation = async (weakPasswords) => {
  for (const password of weakPasswords) {
    const response = await request("http://localhost:4000")
      .post("/auth/register")
      .send({
        email: TestUtils.generateTestEmail(),
        password: password,
        name: "Test User",
      })
      .expect(400);

    expect(response.body.error).to.include("password");
  }
};

/**
 * Standardized session test
 */
const testUnauthenticatedSession = async () => {
  const response = await request("http://localhost:4000")
    .get("/api/session")
    .expect(200);

  expect(response.body.loggedIn).to.be.false;
};

/**
 * Standardized security headers test
 */
const testSecurityHeaders = async () => {
  const response = await request("http://localhost:4000").get("/").expect(200);

  expect(response.headers).to.have.property("x-frame-options");
  expect(response.headers).to.have.property("x-content-type-options");
  expect(response.headers).to.have.property("x-xss-protection");
};

/**
 * Standardized rate limiting test
 */
const testRateLimiting = async (
  endpoint,
  method = "get",
  data = null,
  expectedSuccessStatus = 200,
) => {
  const requests = [];

  for (let i = 0; i < 10; i++) {
    let req = request("http://localhost:4000")[method](endpoint);

    if (data) {
      req = req.send(data);
    }

    const response = await req;
    requests.push(response.status);
  }

  const successCount = requests.filter(
    (status) => status === expectedSuccessStatus,
  ).length;
  expect(successCount).to.be.greaterThan(0);

  const rateLimitCount = requests.filter((status) => status === 429).length;
  expect(rateLimitCount).to.be.at.least(0);
};

/**
 * Standardized SQL injection prevention test
 */
const testSqlInjectionPrevention = async (
  sqlInjectionAttempts,
  endpoint,
  method = "post",
) => {
  for (const attempt of sqlInjectionAttempts) {
    const response = await request("http://localhost:4000")
      [method](endpoint)
      .send({
        email: attempt,
        password: "testpassword",
      })
      .expect(401);

    expect(response.body).to.have.property("error");
  }
};

/**
 * Standardized XSS prevention test
 */
const testXssPrevention = async (xssAttempts, fieldName = "name") => {
  for (const attempt of xssAttempts) {
    const payload = {
      email: TestUtils.generateTestEmail(),
      password: "SecureTest123!@#",
      [fieldName]: attempt,
    };

    const response = await request("http://localhost:4000")
      .post("/auth/register")
      .send(payload)
      .expect(400);

    expect(response.body).to.have.property("error");
  }
};

const SharedTestUtils = {
  testServerHealth,
  testInvalidLogin,
  testUserRegistration,
  testLoginInTestMode,
  testEmailValidation,
  testPasswordValidation,
  testUnauthenticatedSession,
  testSecurityHeaders,
  testRateLimiting,
  testSqlInjectionPrevention,
  testXssPrevention,
};

module.exports = {
  testServerHealth,
  testInvalidLogin,
  testUserRegistration,
  testLoginInTestMode,
  testEmailValidation,
  testPasswordValidation,
  testUnauthenticatedSession,
  testSecurityHeaders,
  testRateLimiting,
  testSqlInjectionPrevention,
  testXssPrevention,
  SharedTestUtils,
};
