import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends HttpServlet {
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException {
		String taint = request.getParameter("page");
		taint = taint.replace("string", "replacement");  // this is currently not a taint step in the default query pack
		response.getWriter().print("a " + taint);
	}
}
