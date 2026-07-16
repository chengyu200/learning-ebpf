import java.util.ArrayList;
import java.util.List;

public class GCTest {
    public static void main(String[] args) throws Exception {
        System.out.println("Java process started, PID: " + ProcessHandle.current().pid());
        List<byte[]> list = new ArrayList<>();
        
        while (true) {
            // 分配内存触发 GC
            for (int i = 0; i < 100; i++) {
                list.add(new byte[1024 * 1024]); // 1MB
            }
            
            // 清空列表,让对象可以被回收
            list.clear();
            
            // 显式建议 GC
            System.gc();
            
            System.out.println("Triggered GC cycle");
            Thread.sleep(2000);
        }
    }
}

