# SQL Commands

## Connection

Connect to the MySQL server as the `root` user and prompt for a password:

```bash
mysql -u root -p
```

## Databases

### Create Database
Creates a new SQL database.

```sql
CREATE DATABASE database_name;
```

### Show Databases
Returns a list of all existing databases.

```sql
SHOW DATABASES;
```

### Use Database
Selects a specific database to perform operations on.

```sql
USE database_name;
```

### Drop Database
Permanently deletes a database and all of its contents.

```sql
DROP DATABASE database_name;
```

## Tables

### Create Table
Creates a new table within the currently in-use database. You must define the column names and their data types.

```sql
CREATE TABLE table_name (
    column1 datatype,
    column2 datatype,
    column3 datatype,
   ....
);
```

**Example:**
```sql
CREATE TABLE Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Show Tables
Lists all tables within the currently selected database.

```sql
SHOW TABLES;
```

### Describe Table
Displays the structure (columns, data types, keys, etc.) of a specific table.

```sql
DESCRIBE table_name;
```

*Note: You can also use `DESC table_name;` as a shorthand.*

### Alter Table
Modifies an existing table's structure (e.g., adding, deleting, or modifying columns).

**Add a column:**
```sql
ALTER TABLE table_name ADD column_name datatype;
```

**Drop a column:**
```sql
ALTER TABLE table_name DROP COLUMN column_name;
```

**Modify a column:**
```sql
ALTER TABLE table_name MODIFY COLUMN column_name datatype;
```

### Drop Table
Permanently deletes a table and all the data within it.

```sql
DROP TABLE table_name;
```

## Data Manipulation (CRUD)

### Create (Insert)
Adds new rows of data into a table.

```sql
INSERT INTO table_name (column1, column2, column3)
VALUES (value1, value2, value3);
```

### Read (Select)
Retrieves and displays data from one or more tables.

**Select all columns:**
```sql
SELECT * FROM table_name;
```

**Select specific columns:**
```sql
SELECT column1, column2 FROM table_name;
```

**Select with a condition:**
```sql
SELECT * FROM table_name WHERE condition;
```

### Update
Modifies existing data within a table. Always use a `WHERE` clause to avoid updating every row!

```sql
UPDATE table_name
SET column1 = value1, column2 = value2
WHERE condition;
```

### Delete
Removes rows of data from a table. Always use a `WHERE` clause to avoid deleting every row!
 
```sql
DELETE FROM table_name WHERE condition;
```

## Advanced Queries (Filtering and Sorting)

### Distinct
Returns only distinct (different) values, eliminating duplicates from the result set.

```sql
SELECT DISTINCT column_name FROM table_name;
```

### Order By
Sorts the result set in ascending (ASC) or descending (DESC) order. Ascending is the default if not specified.

```sql
SELECT column1, column2 
FROM table_name 
ORDER BY column1 ASC, column2 DESC;
```

### Group By
Groups rows that have the same values in specified columns into summary rows, often used with aggregate functions like `COUNT()`, `MAX()`, `MIN()`, `SUM()`, or `AVG()`.

```sql
SELECT column_name, COUNT(*)
FROM table_name
GROUP BY column_name;
```

### Having
Used in combination with the `GROUP BY` clause to restrict the groups of returned rows to only those whose condition is true. It acts like a `WHERE` clause for aggregated data.

```sql
SELECT column_name, COUNT(*)
FROM table_name
GROUP BY column_name
HAVING COUNT(*) > 5;
```

## Operators and Conditions (WHERE Clause)

### Comparison Operators
Used to compare values in conditions.
*   **Equal:** `=`
*   **Not Equal:** `!=` or `<>`
*   **Greater/Less Than:** `>`, `<`, `>=`, `<=`

```sql
SELECT * FROM table_name WHERE column_name != 'value';
```

### AND, OR, NOT
Used to combine or negate conditions.

```sql
-- AND: Both conditions must be true
SELECT * FROM table_name WHERE condition1 AND condition2;

-- OR: At least one condition must be true
SELECT * FROM table_name WHERE condition1 OR condition2;

-- NOT: Negates a condition (true if condition is false)
SELECT * FROM table_name WHERE NOT condition1;
```

### BETWEEN
Selects values within a specified range (inclusive of endpoints). Can be used with numbers, text, or dates.

```sql
SELECT * FROM table_name WHERE column_name BETWEEN value1 AND value2;
```

### LIKE (Pattern Matching)
Used in a `WHERE` clause to search for a specified pattern in a column.
*   `%`: Represents zero, one, or multiple characters.
*   `_`: Represents a single character.

**Starts with 'a':**
```sql
SELECT * FROM table_name WHERE column_name LIKE 'a%';
```

**Contains 'text':**
```sql
SELECT * FROM table_name WHERE column_name LIKE '%text%';
```

**Ends with 'z', 3 characters long:**
```sql
SELECT * FROM table_name WHERE column_name LIKE '__z';
```

## Built-in Functions

### String Functions
Used to manipulate and format text data.

**CONCAT()**
Adds two or more strings together.
```sql
SELECT CONCAT(first_name, ' ', last_name) AS full_name FROM table_name;
```

**GROUP_CONCAT()**
Concatenates data from multiple rows into one continuous string (useful with GROUP BY).
```sql
SELECT group_name, GROUP_CONCAT(username) FROM table_name GROUP BY group_name;
```

**SUBSTRING()**
Extracts a substring from a string (starting at a specific position).
```sql
-- Syntax: SUBSTRING(string, start, length)
SELECT SUBSTRING(column_name, 1, 5) FROM table_name;
```

**LENGTH()**
Returns the length of a string (in bytes).
```sql
SELECT LENGTH(column_name) FROM table_name;
```

### Aggregate Functions
Performs a calculation on a set of values and returns a single value. Often used with the `GROUP BY` clause.

**COUNT()**
Returns the number of rows that match a specified criterion.
```sql
SELECT COUNT(column_name) FROM table_name;
SELECT COUNT(*) FROM table_name; -- Counts all rows
```

**SUM()**
Returns the total sum of a numeric column.
```sql
SELECT SUM(column_name) FROM table_name;
```

**MAX() and MIN()**
Returns the maximum or minimum value in a selected column.
```sql
SELECT MAX(column_name) FROM table_name;
SELECT MIN(column_name) FROM table_name;
```
