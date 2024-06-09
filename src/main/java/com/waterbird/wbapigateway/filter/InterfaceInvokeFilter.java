package com.waterbird.wbapigateway.filter;


import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import com.waterbird.wbapicommon.entity.InterfaceInfo;
import com.waterbird.wbapicommon.entity.User;
import com.waterbird.wbapicommon.service.InnerInterfaceInfoService;
import com.waterbird.wbapicommon.service.InnerUserInterfaceInfoService;
import com.waterbird.wbapicommon.service.InnerUserService;
import com.waterbird.wbapisdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 全局过滤
 */
@Slf4j
@Component
public class InterfaceInvokeFilter implements GatewayFilter, Ordered {

    @DubboReference
    private ApiBackendService apiBackendService;

    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    @Resource
    private StringRedisTemplate stringRedisTemplate;


    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");


    private static final long FIVE_MINUTES = 5 * 60 * 1000L;

    // 接口主机
    private static final String INTERFACE_HOST = "http://localhost:8123";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        String path = INTERFACE_HOST + request.getPath().value();
        // 多了空指针检查，明确了 request.getMethod()不能为空，增加了代码的健壮性和可维护性。
        String method = Objects.requireNonNull(request.getMethod()).toString();

        log.info("请求id：" + request.getId());
        log.info("请求URI："+request.getURI());
        log.info("请求PATH:"+request.getPath());
        log.info("请求方法：" + method);
        log.info("请求参数：" + request.getQueryParams());
        InetSocketAddress sourceAddress = request.getLocalAddress();
        log.info("本地请求地址:"+request.getLocalAddress());
        String remoteAddress = Objects.requireNonNull(request.getRemoteAddress()).getHostString();
        log.info("请求地址：", remoteAddress);

        //2访问控制 -黑白名单
        if (!IP_WHITE_LIST.contains(sourceAddress)) {
            return handleNoAuth(response);
        }

        //3 用户鉴权（API签名认证判断 ak、sk 是否合法）
        HttpHeaders httpHeaders = request.getHeaders();

        String accessKey = httpHeaders.getFirst("accessKey");
        // 防止中文乱码
        String body = null;
        try {
            body = URLDecoder.decode(Objects.requireNonNull(httpHeaders.getFirst("body")), StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        String nonce = httpHeaders.getFirst("nonce");
        String timestamp = httpHeaders.getFirst("timestamp");
        String sign = httpHeaders.getFirst("sign");
        boolean hasBlank = StrUtil.hasBlank(accessKey, body, sign, nonce, timestamp);
        // 判断是否有空
        if (hasBlank) {
            return handleInvokeError(response);
        }
        // 查询用户是否存在
        User invokeUser = null;
        try {
            invokeUser = innerUserService.getInvokeUser(accessKey);
        } catch (Exception e) {
            log.error("getInvokeUser error", e);
        }
        if (invokeUser == null) {
            return handleNoAuth(response);
        }
        // 从数据库中查出 secretKey
        String secrectKey = invokeUser.getSecretKey();
        String serverSign = SignUtils.genSign(body, secrectKey);

        if (sign == null || !StrUtil.equals(sign, serverSign)) {
            log.error("签名校验失败");
            return handleInvokeError(response);
        }


        //3.1防重放，使用redis存储请求的唯一标识，随机时间，并定时淘汰，那使用什么redis结构来实现嗯？
        //既然是单个数据，这样用string结构实现即可
        Boolean success = stringRedisTemplate.opsForValue().setIfAbsent(nonce, "1", 5, TimeUnit.MINUTES);
        if (success ==null){
            log.error("随机数存储失败!!!!");
            return handleNoAuth(response);
        }
        // 时间戳是否为数字
        if (!NumberUtil.isNumber(timestamp)) {
            return handleInvokeError(response);
        }
        // 时间和当前时间不能超过5分钟
        if (System.currentTimeMillis() - Long.parseLong(timestamp) >= FIVE_MINUTES) {
            return handleInvokeError(response);
        }

        // 远程调用请求的模拟接口是否存在？以及获取调用接口信息
        InterfaceInfo invokeInterfaceInfo = null;
        try {
            invokeInterfaceInfo = innerInterfaceInfoService.getInvokeInterfaceInfo(path, method);
        } catch (Exception e) {
            log.error("getInterfaceInfo error", e);
        }
        if (invokeInterfaceInfo == null) {
            return handleInvokeError(response);
        }
        //  是否有调用次数
        if (!innerUserInterfaceInfoService.hasInvokeNum(invokeUser.getId(), invokeInterfaceInfo.getId())) {
            return handleInvokeError(response);
        }

        //请求转发，调用模拟接口
        return handleResponse(exchange, chain, invokeInterfaceInfo.getId(), invokeUser.getId());
    }

    @Override
    public int getOrder() {
        return -1;
    }

    public Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }

    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceInfoId, long userId) {
        try {
            // 获取原始的响应对象
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 获取数据缓冲工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取响应的状态码
            HttpStatus statusCode = originalResponse.getStatusCode();

            // 判断状态码是否为200 OK(按道理来说,现在没有调用,是拿不到响应码的,对这个保持怀疑 沉思.jpg)
            if (statusCode == HttpStatus.OK) {
                // 创建一个装饰后的响应对象(开始穿装备，增强能力)
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

                    // 重写writeWith方法，用于处理响应体的数据
                    // 这段方法就是只要当我们的模拟接口调用完成之后,等它返回结果，
                    // 就会调用writeWith方法,我们就能根据响应结果做一些自己的处理
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        // 判断响应体是否是Flux类型
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 返回一个处理后的响应体
                            // (这里就理解为它在拼接字符串,它把缓冲区的数据取出来，一点一点拼接好)
                            return super.writeWith(fluxBody.map(dataBuffer -> {
                                // 调用成功，接口调用次数 + 1 InvokeCount
                                try {
                                    innerUserInterfaceInfoService.invokeCount(interfaceInfoId, userId);
                                } catch (Exception e) {
                                    log.error("invokeCount error", e);
                                }
                                // 读取响应体的内容并转换为字节数组
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                DataBufferUtils.release(dataBuffer);//释放掉内存
                                // 构建日志
                                StringBuilder sb2 = new StringBuilder(200);
                                List<Object> rspArgs = new ArrayList<>();
                                rspArgs.add(originalResponse.getStatusCode());
                                //rspArgs.add(requestUrl);
                                String data = new String(content, StandardCharsets.UTF_8);//data
                                sb2.append(data);
                                log.info(sb2.toString(), rspArgs.toArray());
                                log.info("响应结果：" + data);
                                // 将处理后的内容重新包装成DataBuffer并返回
                                return bufferFactory.wrap(content);
                            }));
                        } else {
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 对于200 OK的请求,将装饰后的响应对象传递给下一个过滤器链,并继续处理(设置repsonse对象为装饰过的)
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            // 对于非200 OK的请求，直接返回，进行降级处理
            return chain.filter(exchange);
        } catch (Exception e) {
            // 处理异常情况，记录错误日志
            log.error("网关处理异常.\n" + e);
            return chain.filter(exchange);
        }
    }
}