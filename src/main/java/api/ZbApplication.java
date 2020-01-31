package api;

import api.entity.User;
import api.security.jwt.JwtUtil;
import api.security.jwt.UserLoginToken;
import api.service.UserService;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONPObject;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@MapperScan("api.mapper")
public class ZbApplication {
    @Autowired
    private UserService userService;

    public static void main(String[] args) {
        SpringApplication.run(ZbApplication.class, args);
    }
    @RequestMapping("getUser/{id}")
    public String index(@PathVariable  int id){
        return userService.Sel(id).toString();
    }
    @RequestMapping("/login")
    public Map<String,String> login( User user){
       Map<String,String> map = new HashMap<>();


        User userForBase=userService.Sel(Integer.valueOf(user.getId()));
        if(userForBase==null){
            map.put("message","登录失败,用户不存在");
            return map;
        }else {
            if (!userForBase.getPassword().equals(user.getPassword())){
                map.put("message","登录失败,密码错误");
                return map;
            }else {
                String token = JwtUtil.getToken(userForBase);

                map.put("token", token);
                map.put("user", userForBase.toString());
                return map;
            }
        }
    }
    @UserLoginToken
    @GetMapping("/getMessage")
    public String getMessage(){
        return "你已通过验证";
    }

}
