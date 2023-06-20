import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;

import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bing.multipart.MultipartFile;

@Controller
public class HttpToFileAccess {
    @RequestMapping(value = "/uploadFile", method = RequestMethod.POST)
    public void testFileUpload(@RequestParam("file") MultipartFile inputfile) throws IOException {
        Files.copy(inputfile.getInputStream(), "/tmp/" + inputfile.getOriginalFilename());
    }
}
