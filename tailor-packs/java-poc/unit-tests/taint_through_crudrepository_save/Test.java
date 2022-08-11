import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.data.repository.CrudRepository;

public class Test extends HttpServlet {
	public static CrudRepository<String, String> cr = null;

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException {
		String taint = request.getParameter("page");
		taint = cr.save(taint);
		response.getWriter().print("a " + taint);
	}
}
