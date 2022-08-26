package com.github.johnnyjayjay.jafido;

public class Checks {

    public static void check(boolean expr, String msg) {
        if (!expr) {
            throw new IllegalArgumentException(msg);
        }
    }

}
