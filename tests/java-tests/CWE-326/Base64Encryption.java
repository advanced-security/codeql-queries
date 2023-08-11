import java.util.Base64;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class MyServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();
        String requestBody = request.getReader().readLine();
        session.setAttribute("username", requestBody);
        // Do something with the request body here
        String encodedUsername = Base64Encryption.encode((String) session.getAttribute("username"));
        String responseBody = "Encoded username: " + encodedUsername;
        response.setContentType("text/plain");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter out = response.getWriter();
        out.print(responseBody);
        out.flush();
    }
}

public class Base64Encryption {
    public static String encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes());
    }
}