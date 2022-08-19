import java.io.*;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Except extends HttpServlet {
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		//
		Exception err = new Exception("Test");

		// Need to track taint from these functions
		response.getWriter().print("a " + err.getMessage());
		response.getWriter().print("a " + err.toString());

		// Other case (unsupported right now)
		response.getWriter().print("a " + err);
	}
}
