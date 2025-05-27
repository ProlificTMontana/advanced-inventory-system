# Advanced-inventory-system

In today’s fast-paced digital world, managing inventory manually is not only outdated but risky. Whether you’re running a warehouse, small business, or an e-commerce store, an efficient inventory management system is critical.

This **Advanced Inventory Management System** is built using **Python** with a **modern UI in PyQt5**, featuring **real-time stock updates**, a **dashboard with analytics**, **robust data management**, **report export features**, and more.

## Project Overview

This project provides a deployable and fully customizable inventory management solution. It is designed for ease of use, professional appearance, and operational robustness.

---

## Tech Stack

| Component        | Technology      |
|------------------|-----------------|
| Language          | Python 3        |
| GUI Library       | PyQt5           |
| Database          | SQLite          |
| Data Handling     | Pandas          |
| Charts & Graphs   | Matplotlib      |
| Editors           | Sublime Text 3, VS Code |

---

## Key Features

### 🔐 Authentication System
- Secure login with password hashing
- Role-based access control
- Default Admin Account:  
  `Username: admin`  
  `Password: admin`

### 📊 Modern Dashboard
- Real-time statistics (Total Items, Low Stock, Categories)
- Interactive bar charts with color-coded stock levels
- Clean and professional modern UI

### 📦 Item Management
- Add, update, delete items with form validation
- Real-time search and filtering by category
- Visual low-stock alerts (highlighted in red)
- Detailed item attributes (name, category, quantity, price, minimum stock, supplier)

### 🗃️ Category Management
- Dynamic category creation and editing
- Filter items by category
- Add category descriptions for better clarity

### 📈 Advanced Reporting
- Generate low stock and full inventory reports
- Category-wise analysis
- Real-time report generation with summaries

### 💾 Export Capabilities
- Export inventory and reports to Excel using Pandas
- Generate styled PDF reports
- Customize export formats and options

### 🎨 Professional UI/UX
- Flat design with modern aesthetics
- Color-coded UX elements
- Responsive layout with tabbed navigation
- Intuitive toolbar with quick-access actions

### 🗄️ Robust Data Management
- SQLite database with normalized structure
- Automatic database setup and initialization
- Comprehensive error handling and validations
- Transaction-safe operations

---

# Running the Project

    Clone the repository:

     git clone https://github.com/ProlifiTMontana/advanced-inventory-system.git

     cd advanced-inventory-system

   Run the main application:

     python main.py

    Login using:

        Username: admin

        Password: admin

📝 Customization

You can easily extend or modify:

    UI using .ui files and Qt Designer

    Reports in reports/

    Authentication logic in utils/auth.py

    Database schema in database/

📄 License

This project is open-source and available under the MIT License.


