# test_setup.py
from config import TARGET_PROGRAMS, GITHUB_HEADERS

def main():
    print("✅ تم تحميل الإعدادات بنجاح!")
    print(f"🎯 عدد الشركات المستهدفة حالياً: {len(TARGET_PROGRAMS)}")
    print("\nقائمة الشركات:")
    for prog in TARGET_PROGRAMS:
        print(f" - {prog['name']} (Organization: {prog['org']})")

if __name__ == "__main__":
    main()