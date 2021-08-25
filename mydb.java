import java.sql.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.lang.*;
import java.math.*;

public class Project3 {
	static final String JDBC_DRIVER = "oracle.jdbc.OracleDriver";
	static final String DB_URL = "server_url";
	static final String USER = "user";
	static final String PASS = "password";
	static Connection conn = null;
	static boolean admin_flag = false;
	static int current_user = 0;

	//exectue command and return result string for output.txt
	public static String execute_command(String command) {
		if (command.startsWith("LOGIN", 0)) {
			return login(command);
		}
		else if (command.startsWith("CREATE ROLE", 0)) {
			return create_role(command);
		}
		else if (command.startsWith("CREATE USER", 0)) {
			return create_user(command);
		}
		else if (command.startsWith("GRANT ROLE", 0)) {
			return grant_role(command);
		}
		else if (command.startsWith("GRANT PRIVILEGE", 0)) {
			return grant_privilege(command);
		}
		else if (command.startsWith("REVOKE PRIVILEGE", 0)) {
			return revoke_privilege(command);
		}
		else if (command.startsWith("INSERT INTO", 0)) {
			return insert_into(command);
		}
		else if (command.startsWith("SELECT", 0)) {
			return select_from(command);
		}
		return "QUIT";
	}

	// update the table by sql query
	public static void update(String query) {
		try {
			Statement stmt_new = conn.createStatement();
			stmt_new.executeUpdate(query);
			stmt_new.close();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	// execute the sql query and return the result table as a list of array list.
	public static ArrayList<ArrayList<String>> execute_sql(String query) {
		Statement stmt = null;
		ArrayList<ArrayList<String>> table = new ArrayList<ArrayList<String>>();
		try {
			stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(query);
			ResultSetMetaData rsmd = rs.getMetaData();
			while (rs.next()) {
				ArrayList <String> row = new ArrayList<String>();
				for (int i = 1; i <= rsmd.getColumnCount(); i++) {
					row.add(rs.getString(i));
				}
				table.add(row);
			}
			rs.close();
			stmt.close();
		}catch(SQLException se) {
			se.printStackTrace();
		}catch(Exception e) {
			e.printStackTrace();
		}finally{
			try{
				if (stmt != null) {
					stmt.close();
				}
			}catch(SQLException se) {
				se.printStackTrace();
			}
		}
		return table;
	}
	public static ArrayList<String> get_header_sql(String query) {
		Statement stmt = null;
		ArrayList<String> header_list = new ArrayList<String>();
		try {
			stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(query);
			ResultSetMetaData rsmd = rs.getMetaData();
			int col_count = rsmd.getColumnCount();
			for (int i = 1; i <= col_count; i++) {
				String header = rsmd.getColumnName(i);
				header_list.add(header);
			}
			rs.close();
			stmt.close();
		}catch(SQLException se) {
			se.printStackTrace();
		}catch(Exception e) {
			e.printStackTrace();
		}finally{
			try{
				if (stmt != null) {
					stmt.close();
				}
			}catch(SQLException se) {
				se.printStackTrace();
			}
		}
		return header_list;

	}
	// Autokey Cipher 
	public static String Autokey_Cipher_Encry(String plaintext, String key){
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		String text = ""; //text without special chars and uppercase every letter.
		for (int i = 0; i < plaintext.length(); i++) {
			char c = plaintext.charAt(i);
			if (Character.isLetter(c)) {
				c = Character.toUpperCase(c);
				text = text + c;
			}
		}
		key = key.toUpperCase();  //key is case-insensitive
		String prepend_key = key + text;
		prepend_key = prepend_key.substring(0, text.length());
		String ciphertext = "";
		for (int j = 0; j < text.length(); j++) {
			int add1 = alphabet.indexOf(text.charAt(j));
			int add2 = alphabet.indexOf(prepend_key.charAt(j));
			int final_add = (add1 + add2) % 26;
			ciphertext = ciphertext + alphabet.charAt(final_add);
		}
		//insert special chars
		String output = "";
		int count = 0;
		for (int k = 0; k < plaintext.length(); k++) {
			char insert_c = plaintext.charAt(k);
			if (Character.isLetter(insert_c)) {
				if (Character.isLowerCase(insert_c)) {
					output = output + Character.toLowerCase(ciphertext.charAt(count));
					count++;
				}
				else {
					output = output + ciphertext.charAt(count);
					count++;
				}
			}
			else {
				output = output + insert_c;
			}

		}
		return output;
	}
	public static String Autokey_Cipher_Decry(String ciphertext, String key){
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		String text = ""; //text without special chars and uppercase every letter.
		for (int i = 0; i < ciphertext.length(); i++) {
			char c = ciphertext.charAt(i);
			if (Character.isLetter(c)) {
				c = Character.toUpperCase(c);
				text = text + c;
			}
		}
		key = key.toUpperCase();  //key is case-insensitive
		String plaintext = "";
		for (int j = 0; j < text.length(); j++) {
			int add1 = alphabet.indexOf(text.charAt(j));
			int add2;
			if (j < key.length()) {
				add2 = alphabet.indexOf(key.charAt(j));
			}
			else {
				add2 = alphabet.indexOf(plaintext.charAt(j - key.length()));

			}

			int final_add = (add1 - add2) % 26;
			if (final_add < 0) {
				final_add = final_add + 26;
			}
			plaintext = plaintext + alphabet.charAt(final_add);
		}
		//insert special chars
		String output = "";
		int count = 0;
		for (int k = 0; k < ciphertext.length(); k++) {
			char insert_c = ciphertext.charAt(k);
			if (Character.isLetter(insert_c)) {
				if (Character.isLowerCase(insert_c)) {
					output = output + Character.toLowerCase(plaintext.charAt(count));
					count++;
				}
				else {
					output = output + plaintext.charAt(count);
					count++;
				}
			}
			else {
				output = output + insert_c;
			}

		}
		return output;
	}
	//LOGIN COMMAND
	public static String login(String command) {
		String[] buffer = command.split(" ");
		String user = buffer[1];
		String pass = buffer[2];
		String query = "select * from users where username = \'" + user + "\' and password = \'" + pass + "\'";
		ArrayList<ArrayList<String>> table = execute_sql(query);
		if (table.size() == 0) {
			admin_flag = false;
			return "Invalid login";
		}
		else {
			if (user.equals("admin")) {
				admin_flag = true;
			}
			else {
				admin_flag = false;
			}
			current_user = Integer.parseInt(table.get(0).get(0));
			return "Login successful";
		}
	}
	//CREATE ROLE
	public static String create_role(String command) {
		String[] buffer = command.split(" ");
		String role_name = buffer[2];
		String key = buffer[3];
		if (!admin_flag) {
			return "Authorization failure";
		}
		else {
			ArrayList<ArrayList<String>> table = execute_sql("select max(roleid) from roles");
    		int max_id = Integer.parseInt(table.get(0).get(0));
    		String update_query = 
    		String.format("INSERT INTO Roles VALUES (%d, \'%s\', \'%s\')",max_id + 1, role_name, key);
    		update(update_query);
    		return "Role created successfully";

		}
	}
	public static String create_user(String command) {
		String[] buffer = command.split(" ");
		String user = buffer[2];
		String pass = buffer[3];
		if (!admin_flag) {
			return "Authorization failure";
		}
		else {
			ArrayList<ArrayList<String>> table = execute_sql("select max(userid) from users");
    		int max_id = Integer.parseInt(table.get(0).get(0));
    		String update_query = 
    		String.format("INSERT INTO Users VALUES (%d, \'%s\', \'%s\')",max_id + 1, user, pass);
    		update(update_query);
    		return "User created successfully";

		}
	}
	public static String grant_role(String command) {
		String[] buffer = command.split(" ");
		String user = buffer[2];
		String role_name = buffer[3];
		if (!admin_flag) {
			return "Authorization failure";
		}
		else {
			ArrayList<ArrayList<String>> table1 = execute_sql("select userid from users where username = \'" + user + "\'");
			int user_id = Integer.parseInt(table1.get(0).get(0));
			ArrayList<ArrayList<String>> table2 = execute_sql("select roleid from roles where rolename = \'" + role_name + "\'");
			int role_id = Integer.parseInt(table2.get(0).get(0));
			String update_query = 
    		String.format("INSERT INTO UsersRoles VALUES (%d, %d)",user_id, role_id);
    		update(update_query);
    		return "Role assigned successfully";

		}

	}
	public static String grant_privilege(String command) {
		String[] buffer = command.split(" ");
		String privilege_name = buffer[2];
		String role_name = buffer[4];
		String table_name = buffer[6];
		if (!admin_flag) {
			return "Authorization failure";
		}
		else {
			ArrayList<ArrayList<String>> table1 = execute_sql("select privid from privileges where privname = \'" + privilege_name + "\'");
			int privilege_id = Integer.parseInt(table1.get(0).get(0));
			ArrayList<ArrayList<String>> table2 = execute_sql("select roleid from roles where rolename = \'" + role_name + "\'");
			int role_id = Integer.parseInt(table2.get(0).get(0));
			String update_query = 
    		String.format("INSERT INTO RolesPrivileges VALUES (%d, %d, \'%s\')",role_id, privilege_id, table_name);
    		update(update_query);
    		return "Privilege granted successfully";

		}
	}
	public static String revoke_privilege(String command) {
		String[] buffer = command.split(" ");
		String privilege_name = buffer[2];
		String role_name = buffer[4];
		String table_name = buffer[6];
		if (!admin_flag) {
			return "Authorization failure";
		}
		else {
			ArrayList<ArrayList<String>> table1 = execute_sql("select privid from privileges where privname = \'" + privilege_name + "\'");
			int privilege_id = Integer.parseInt(table1.get(0).get(0));
			ArrayList<ArrayList<String>> table2 = execute_sql("select roleid from roles where rolename = \'" + role_name + "\'");
			int role_id = Integer.parseInt(table2.get(0).get(0));
			String update_query = 
    		String.format("delete from rolesprivileges where roleid = %d and privid = %d and TableName = \'%s\'",role_id,privilege_id,table_name);
    		update(update_query);
    		return "Privilege revoked successfully";

		}
	}
	public static String insert_into(String command) {
		String[] buffer = command.split(" ");
		String table_name = buffer[2];
		int col_num = Integer.parseInt(buffer[buffer.length - 2]);
		String owner_role = buffer[buffer.length - 1];
		String check_role_query = "select roleid from rolesprivileges where privid = 1 and tablename = \'" + table_name + "\'";
		ArrayList<ArrayList<String>> check_role_table = execute_sql(check_role_query);
		boolean check_permission = false;
		for (ArrayList<String> row : check_role_table) {
			int role_id = Integer.parseInt(row.get(0));
			String check_user_query = 
			String.format("select * from usersroles where userid = %d and roleid = %d", current_user, role_id);
			ArrayList<ArrayList<String>> check_user_table = execute_sql(check_user_query);
			if (check_user_table.size() > 0) {
				check_permission = true;
				break;
			}
		}
		Matcher m = Pattern.compile("\\(([^)]+)\\)").matcher(command);
		if (check_role_table.size() == 0 || !check_permission || !m.find()) {
			return "Authorization failure";
		}
		else {
			String[] value_list_with_quote = m.group(1).split(",");
			ArrayList<String> value_list = new ArrayList<String>();
			for (String s : value_list_with_quote) {
				if (s.charAt(0) != ' ') {
					value_list.add(s.substring(1, s.length() - 1));
				}
				else {
					value_list.add(s.substring(2, s.length() - 1));
				}
			}
			String new_query = String.format("select roleId,encryptionKey from roles where rolename = \'%s\'",owner_role);
			ArrayList<ArrayList<String>> table = execute_sql(new_query);
			int owner_role_id = Integer.parseInt(table.get(0).get(0));
			String encryption_key = table.get(0).get(1);
			if (col_num > 0) {
				value_list.set(col_num - 1, Autokey_Cipher_Encry(value_list.get(col_num-1), encryption_key));
			}
			value_list.add(Integer.toString(col_num));
			value_list.add(Integer.toString(owner_role_id));
			String update_query = String.format("INSERT INTO %s VALUES(", table_name);
			for (String value : value_list) {
				update_query = update_query + "\'" + value + "\'" + ",";
			}
			update_query = update_query.substring(0, update_query.length()-1) + ")";
			System.out.println(update_query);
			update(update_query);
			return "Row inserted successfully";
		}
	}
	public static String select_from(String command) {
		String[] buffer = command.split(" ");
		String table_name = buffer[3];
		String check_role_query = "select roleid from rolesprivileges where privid = 2 and tablename = \'" + table_name + "\'";
		ArrayList<ArrayList<String>> check_role_table = execute_sql(check_role_query);
		boolean check_permission = false;
		for (ArrayList<String> row : check_role_table) {
			int role_id = Integer.parseInt(row.get(0));
			String check_user_query = 
			String.format("select * from usersroles where userid = %d and roleid = %d", current_user, role_id);
			ArrayList<ArrayList<String>> check_user_table = execute_sql(check_user_query);
			if (check_user_table.size() > 0) {
				check_permission = true;
				break;
			}
		}
		if (check_role_table.size() == 0 || !check_permission) {
			return "Authorization failure";
		}
		else {
			String select_sql = "select * from " + table_name;
			ArrayList<ArrayList<String>> table = execute_sql(select_sql);
			ArrayList<String> header_row = get_header_sql(select_sql);
			String output = "";

			for (int i = 0; i < header_row.size() - 3; i++) {
				output = output + header_row.get(i) + ", ";
				// System.out.println("header is " + header_row.get(i));
			}
			output = output + header_row.get(header_row.size() - 3) + "\n";
			for (int j = 0; j < table.size(); j++) {
				ArrayList<String> row = table.get(j);
				int owner_role_id = Integer.parseInt(row.get(row.size() - 1));
				int encrypted_col = Integer.parseInt(row.get(row.size() - 2));
				//check if current user has the owner_role
				String check = String.format("select * from usersroles where userid = %d and roleid = %d",current_user,owner_role_id);
				ArrayList<ArrayList<String>> check_table = execute_sql(check);
				if (check_table.size() == 0) {
					// current user does not have the owner_role
					for (int a = 0; a < row.size() - 3; a++) {
						output = output + row.get(a) + ", ";
					}
					output = output + row.get(row.size() -3);
				}
				else {
					// decrypt the request col
					String select_key = String.format("select encryptionkey from roles where roleId = %d",owner_role_id);
					ArrayList<ArrayList<String>> new_table = execute_sql(select_key);
					String key = new_table.get(0).get(0);
					for (int a= 0; a < row.size() - 2; a++) {
						if (a + 1 == encrypted_col) {
							output = output + Autokey_Cipher_Decry(row.get(a), key) + ", ";
						}
						else {
							output = output + row.get(a) + ", ";
						}
					}
					output = output.substring(0, output.length() - 2);
				}
				if (j != table.size() - 1) {
					output = output + "\n";
				}
			}
			return output;
		}
	}



























	public static void main(String[] args) {
		// String test_string = Autokey_Cipher_Encry("Data @ Base 1DATABASE....", "KEY");
		// System.out.println(test_string);
		// String test_string2 = Autokey_Cipher_Decry("Nerd @ Btsf 1DSXDBTSF....", "KEY");
		// System.out.println(test_string2);


		try{
      //STEP 2: Register JDBC driver
			Class.forName(JDBC_DRIVER);

      //STEP 3: Open a connection
			System.out.println("Connecting to database...");
			conn = DriverManager.getConnection(DB_URL,USER,PASS);

		}catch(Exception e){
			e.printStackTrace();
		}
		ArrayList<String> command_list = new ArrayList<String>();
		// read from input
		try {
			BufferedReader br = new BufferedReader(new FileReader(args[0]));
			String s;
			try {
				while ((s = br.readLine()) != null) {
					command_list.add(s);
				}
				br.close();
			}catch(IOException e) {
				e.printStackTrace();
			}

		}catch(FileNotFoundException e) {
			e.printStackTrace();
		}
		//write to output
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(args[1]));
			int index = 1;
			for (String command : command_list) {
				String result = execute_command(command);
				bw.write(index + ": " + command + "\n");
				if (!result.equals("QUIT")) {
					bw.write(result + "\n");
					bw.write("\n");
				}
				else {
					// bw.write("\n");
					break;
				}
				index++;
			}
			bw.close();

		}catch(IOException e) {
			e.printStackTrace();
		}


		// close conn
		try{
         	if(conn!=null)
            	conn.close();
            // System.out.println("Goodbye first!");
      	}catch (SQLException se){
         	se.printStackTrace();
      	}
   		System.out.println("Goodbye!");
	}
}
