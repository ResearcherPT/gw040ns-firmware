# gw040ns-firnware
### bạn sẽ được học cách mod firmware ,một cách miễn phí

> [!CAUTION]
> **⚠️ Miễn trừ trách nhiệm ⚠️**<br>
> Tất cả nội dung chỉ nhằm mục đích nghiên cứu, học tập.<br>
> Không khuyến khích sử dụng vào các hoạt động vi phạm pháp luật hay xâm phạm hệ thống mạng.<br>
> Người sử dụng hoàn toàn tự chịu trách nhiệm.<br>
> Việc thực hiện theo các hành động đề cập trong này (kể cả cài ứng dụng) có thể khiến bạn mất internet hoặc hư hỏng router.

# #1: dump firmware
```bash
/userfs/bin/mtd readflash /tmp/tclinux_stock.bin ffffffff 0 mtd4
```
lệnh này sẽ tạo trong /tmp một file tên tclinux_stock.bin, bạn sử dụng các app như winscp/filezilla để tải file này về
# #2: chuẩn bị
hãy tạo thư mục với cấu trúc như sau
```
gw040_work/
├── images/
│   └── tclinux_stock.bin
├── rootfs_modded/
└── out/
```
đối với ubuntu thì: ```sudo apt install -y python3 device-tree-compiler squashfs-tools sshpass```

còn linux nói chung và cachyos nói riêng: ```sudo pacman -S --needed python dtc squashfs-tools sshpass```
# #3: kiểm tra tinh toàn vẹn
tải tool ngay tại đây
sau đó chạy lệnh sau
```bash
python3 g040ns_unified_tool.py inspect \
  --project-dir ./gw040_work \
  images/tclinux_stock.bin
```
(hãy nhớ mang file tclinux_stock.bin bỏ vào trong /gw040_work/images)
sau khi nhập xong bạn sẽ có các giá trị như sau
```
file_size
hdr_total_size
fit_size
hdr_crc
computed_crc
version
product
kernel_size_hdr
rootfs_size_hdr
sha1/stored_sha1 của fdt@1, kernel@1, filesystem@1
```
bạn có thể sử dụng AI để kiểm tra các giá trị và phải tuân thủ theo quy tắc sau:
```
hdr_crc == computed_crc
sha1 == stored_sha1
file_size == partition size
```
nếu đúng thì bạn có thể tiếp tục nhưng sai thì bạn phải dump lại và thử ở mtd của tclinux_slave

# #4: giải nén
```bash
python3 g040ns_unified_tool.py extract \
  --project-dir ./gw040_work \
  --out-dir extracted_stock \
  images/tclinux_stock.bin
```
thì sẽ tạo ra folder extracted_stock trong gw040_work, và bạn chỉ cần để ý file tên là rootfs.squashfs 

tiếp đến hãy nhập lệnh sau: 

```bash
sudo unsquashfs rootfs.squashfs
```
và bạn sẽ có 1 folder tên là squashfs-root | nơi mà những file chính router đang chạy (không hoàn toàn 100%)

sau đó có thể xài ```sudo mv``` để bê hết đem tới ```/gw040_work/rootfs_modded/``` để nấu nướng

# #5: đóng gói
```bash
python3 g040ns_unified_tool.py build \
  --project-dir ./gw040_work \
  --base images/tclinux_stock.bin \
  --rootfs-dir rootfs_modded \
  --work-dir work \
  --out out/tclinux_modded.bin
```
và trong folder out sẽ có file bin tên tclinux_modded

nếu bạn là người có tính cẩn thận thì quay lại bước 3 để kiểm tra 

# #6: flash
```bash
python3 g040ns_unified_tool.py flash \
  --project-dir ./gw040_work \
  --image out/tclinux_modded.bin \
  --host 192.168.1.1 \
  --user admin \
  --password 'VnT3ch@dm1n'
```
thì bước này nếu bạn có xài [myshell](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/myshell) thì hãy restart dropbear để bắt đầu
và việc của bạn là chờ và chờ
# Cảm ơn bạn đã đọc 💓
### AppleSang 🍎
