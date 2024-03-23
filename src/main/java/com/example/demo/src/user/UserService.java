package com.example.demo.src.user;



import com.example.demo.common.entity.BaseEntity.State;
import com.example.demo.common.exceptions.BaseException;
import com.example.demo.common.oauth.KISA_SEED_CBC;
import com.example.demo.src.user.entity.User;
import com.example.demo.src.user.model.*;
import com.example.demo.utils.JwtService;
import com.example.demo.utils.SHA256;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.example.demo.common.entity.BaseEntity.State.*;
import static com.example.demo.common.response.BaseResponseStatus.*;

// Service Create, Update, Delete 의 로직 처리
@Transactional
@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    @Value("${spring.encrypted.pbszUserKey}")
    private String PBSZ_USER_KEY;
    @Value("${spring.encrypted.pbszIV}")
    private String PBSZ_IV;


    //POST
    public PostUserRes createUser(PostUserReq postUserReq) {
        //중복 체크
        Optional<User> checkUser = userRepository.findByEmail(postUserReq.getEmail());
        if(checkUser.isPresent() == true){
            State state = checkUser.get().getState();
            if(state==ACTIVE) throw new BaseException(POST_USERS_EXISTS_EMAIL);
            else if(state==DORMANT) throw new BaseException(POST_USERS_EXISTS_DORMANT);
            else if (state==INACTIVE) throw new BaseException(POST_USERS_EXISTS_INACTIVE);
            else if (state==BLOCKED) throw new BaseException(POST_USERS_EXISTS_BLOCKED);
        }

        String encryptPwd;
        try {
            encryptPwd = new SHA256().encrypt(postUserReq.getPassword());
            postUserReq.setPassword(encryptPwd);
        } catch (Exception exception) {
            throw new BaseException(PASSWORD_ENCRYPTION_ERROR);
        }

        String encodeEmail = encrytedMessage(postUserReq.getEmail());
        String encodeName = encrytedMessage(postUserReq.getName());

        postUserReq.setEmail(encodeEmail);
        postUserReq.setName(encodeName);

        User saveUser = userRepository.save(postUserReq.toEntity());
        return new PostUserRes(saveUser.getId());

    }

    public PostUserRes createOAuthUser(User user) {
        User saveUser = userRepository.save(user);

        // JWT 발급
        String jwtToken = jwtService.createJwt(saveUser.getId());
        return new PostUserRes(saveUser.getId(), jwtToken);

    }

    public void modifyUserName(Long userId, PatchUserReq patchUserReq) {
        User user = userRepository.findByIdAndState(userId, ACTIVE)
                .orElseThrow(() -> new BaseException(NOT_FIND_USER));
        user.updateName(patchUserReq.getName());
    }

    public void deleteUser(Long userId) {
        User user = userRepository.findByIdAndState(userId, ACTIVE)
                .orElseThrow(() -> new BaseException(NOT_FIND_USER));
        user.deleteUser();
    }

    @Transactional(readOnly = true)
    public List<GetUserRes> getUsers() {
        List<GetUserRes> getUserResList = userRepository.findAllByState(ACTIVE).stream()
                .map(GetUserRes::new)
                .collect(Collectors.toList());
        return getUserResList;
    }

    @Transactional(readOnly = true)
    public List<GetUserRes> getUsersByEmail(String email) {
        List<GetUserRes> getUserResList = userRepository.findAllByEmailAndState(email, ACTIVE).stream()
                .map(GetUserRes::new)
                .collect(Collectors.toList());
        return getUserResList;
    }


    @Transactional(readOnly = true)
    public GetUserRes getUser(Long userId) {
        User user = userRepository.findByIdAndState(userId, ACTIVE)
                .orElseThrow(() -> new BaseException(NOT_FIND_USER));
        return new GetUserRes(user);
    }

    @Transactional(readOnly = true)
    public boolean checkUserByEmail(String email) {
        Optional<User> result = userRepository.findByEmailAndState(email, ACTIVE);
        if (result.isPresent()) return true;
        return false;
    }

    public PostLoginRes logIn(PostLoginReq postLoginReq) {
        User user = userRepository.findByEmailAndState(postLoginReq.getEmail(), ACTIVE)
                .orElseThrow(() -> new BaseException(NOT_FIND_USER));

        String encryptPwd;
        try {
            encryptPwd = new SHA256().encrypt(postLoginReq.getPassword());
        } catch (Exception exception) {
            throw new BaseException(PASSWORD_ENCRYPTION_ERROR);
        }

        if(user.getPassword().equals(encryptPwd)){
            Long userId = user.getId();
            String jwt = jwtService.createJwt(userId);
            return new PostLoginRes(userId,jwt);
        } else{
            throw new BaseException(FAILED_TO_LOGIN);
        }

    }

    public GetUserRes getUserByEmail(String email) {
        User user = userRepository.findByEmailAndState(email, ACTIVE).orElseThrow(() -> new BaseException(NOT_FIND_USER));
        return new GetUserRes(user);
    }

    private String encrytedMessage(String text){
        byte[] pbszUserKey = PBSZ_USER_KEY.getBytes();
        byte[] pbszIV = PBSZ_IV.getBytes();
        byte[] encrytedMessage = KISA_SEED_CBC.SEED_CBC_Encrypt(pbszUserKey, pbszIV, text.getBytes(), 0, text.getBytes().length);

        return encrytedMessage.toString();
    }

    private String decrytedMessage(String encryteMessage){
        byte[] pbszUserKey = PBSZ_USER_KEY.getBytes();
        byte[] pbszIV = PBSZ_IV.getBytes();
        byte[] decrytedMessage = KISA_SEED_CBC.SEED_CBC_Decrypt(pbszUserKey, pbszIV, encryteMessage.getBytes(), 0, encryteMessage.getBytes().length);

        return decrytedMessage.toString();
    }
}
