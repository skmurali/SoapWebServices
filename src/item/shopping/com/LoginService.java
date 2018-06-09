package item.shopping.com;

import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;
import javax.jws.soap.SOAPBinding.Use;

@WebService(name="LoginService")
@SOAPBinding(style = Style.DOCUMENT, use = Use.LITERAL)

public interface LoginService {
	
	
	public String getLoginidPassword(String loginid, String password) ;



}
