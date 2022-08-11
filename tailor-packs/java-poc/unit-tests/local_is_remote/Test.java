import java.io.*;
import java.net.InetAddress;
import java.nio.file.Path;
import java.nio.file.FileSystems;

class Test {
	void doGet1(InetAddress address)
		throws IOException {
			String temp = address.getHostName();
			
			// BAD: construct a file path with user input
			File file = new File(temp);

			// MAYBE BAD: construct a path with local user input
			Path path = FileSystems.getDefault().getPath(System.getenv("PATH"));
	}
}
