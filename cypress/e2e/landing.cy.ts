describe('Landing Page', () => {
  it('should display landing page at root', () => {
    cy.visit('/');
    cy.contains('Advanced Inventory Management System').should('be.visible');
    cy.contains('Intelligent Inventory Control').should('be.visible');
  });

  it('should have Get Started button that navigates to login', () => {
    cy.visit('/');
    cy.contains('Get Started').click();
    cy.url().should('include', '/login');
  });

  it('should display feature sections', () => {
    cy.visit('/');
    cy.contains('Easy to Navigate').should('be.visible');
    cy.contains('Concise Analytics').should('be.visible');
    cy.contains('Team Efficiency').should('be.visible');
  });
});
