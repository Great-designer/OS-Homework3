#ifndef VM_PAGE_H
#define VM_PAGE_H

#include<hash.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

struct page//����ҳ��
{
//����ĳ�Ա
	void *addr;//�û������ַ
	bool read_only;//ֻ��ҳ
	struct thread *thread;//ӵ���߳�
//�������������������з���
	struct hash_elem hash_elem;//�����̡߳�pages����ϣԪ��
//����ӵ��frame->frame_lock�Ľ��������������ñ������������ɨ��������frame->frame_lock���ֵ������
	struct frame *frame;//ҳ����
//������Ϣ����frame->frame_lock����
	block_sector_t sector;//����������ʼ��������-1
//�ڴ�ӳ���ļ���Ϣ����frame->frame_lock����
	bool private;//Falseд���ļ���trueд��swap
	struct file *file;//�ļ�
	off_t file_offset;//�ļ��е�ƫ����
	off_t file_bytes;//Ҫ��/д���ֽڣ�1pg��С
};

void page_exit(void);

struct page *page_allocate(void *,bool read_only);
void page_deallocate(void *vaddr);

bool page_in(void *fault_addr);
bool page_out(struct page *);
bool page_accessed_recently(struct page *);

bool page_lock(const void *,bool will_write);
void page_unlock(const void *);

hash_hash_func page_hash;
hash_less_func page_less;

#endif /* vm/page.h */
