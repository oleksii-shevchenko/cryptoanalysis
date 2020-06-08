package dev.flanker.ca.analysis;

public class Differential {
    private int a;
    private int b;

    public Differential(int a, int b) {
        this.a = a;
        this.b = b;
    }

    public int getA() {
        return a;
    }

    public void setA(int a) {
        this.a = a;
    }

    public int getB() {
        return b;
    }

    public void setB(int b) {
        this.b = b;
    }

    @Override
    public String toString() {
        return "Differential{" +
                "a=" + a +
                ", b=" + b +
                '}';
    }
}
