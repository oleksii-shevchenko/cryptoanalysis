package dev.flanker.ca.analysis;

import java.util.Objects;

public class Differential {
    private int a;
    private int b;

    private int level;

    public Differential(int a, int b) {
        this.a = a;
        this.b = b;
    }

    public Differential(int a, int b, int level) {
        this.a = a;
        this.b = b;
        this.level = level;
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

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    @Override
    public String toString() {
        return "Differential{" +
                "a=" + a +
                ", b=" + b +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Differential that = (Differential) o;
        return a == that.a &&
                b == that.b;
    }

    @Override
    public int hashCode() {
        return Objects.hash(a, b);
    }
}
