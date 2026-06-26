describe('Authentication', () => {
  beforeEach(() => {
    cy.visit('/login');
  });

  it('should display login form', () => {
    cy.get('input[type="email"]').should('exist');
    cy.get('input[type="password"]').should('exist');
    cy.get('button[type="submit"]').should('exist');
    cy.contains('Sign In to AIMS').should('be.visible');
  });

  it('should show error for invalid credentials', () => {
    cy.get('input[type="email"]').type('invalid@test.com');
    cy.get('input[type="password"]').type('wrongpassword');
    cy.get('button[type="submit"]').click();
    
    cy.get('.bg-red-50').should('be.visible');
  });

  it('should successfully login with valid credentials', () => {
    cy.get('input[type="email"]').type('s.jenkins@aimspwa.com');
    cy.get('input[type="password"]').type('AdminPassword123!');
    cy.get('button[type="submit"]').click();
    
    cy.url().should('include', '/dashboard');
  });

  it('should redirect to dashboard after successful login', () => {
    cy.get('input[type="email"]').type('m.vance@aimspwa.com');
    cy.get('input[type="password"]').type('ManagerPassword123!');
    cy.get('button[type="submit"]').click();
    
    cy.url().should('include', '/dashboard');
    cy.contains('Dashboard').should('be.visible');
  });
});
