package com.github.highcumontoa.authaccesscontroljava.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注资源归属要求：路径变量名由 pathVariable 指定，必须与令牌主体一致（管理员可豁免）。 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SubjectScoped {
    String pathVariable() default "userId";
}
