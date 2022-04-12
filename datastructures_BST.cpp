
#include <iostream>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

struct node
{
	node* left;
	node* right;
	int data;
};

class BinSearchTree
{
	node* root;
public:
	BinSearchTree()
	{
		root = NULL;
	}
	int empty() { return root == NULL; }
	void insert(int newNode);
	void display();
	void print(node*);

};

void BinSearchTree::insert(int newNode)
{
	node* p = new node;
	node* prev;
	p->data = newNode;
	p->left = NULL;
	p->right = NULL;
	prev = NULL;

	if (empty()) { root = p; }
	else
	{
		node* ptr; //Tree Traversal Pointer
		ptr = root;

		while (ptr != NULL)
		{
			prev = ptr;
			if (newNode > ptr->data) { ptr = ptr->right; }
			else { ptr = ptr->left; }

		}
		if (newNode < prev->data) { prev->left = p; }
		else { prev->right = p; }
		//}
	}
}

void BinSearchTree::display()
{ print(root); }

void BinSearchTree::print(node* ptr)
{
	if (ptr != NULL)
	{
		print(ptr->left);
		std::cout << (ptr->data) << cout::endl;;
		print(ptr->right);
	}
}
int main()
{
	srand(time(NULL));
	BinSearchTree myTree;
	for (int i = 0; i < 30; i++)
	{
		myTree.insert(rand() % 100 + 1);
	}

	myTree.display();
	return 0;
}
