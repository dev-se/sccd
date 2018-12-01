public class Person
{
    
    //public Person(string name, int age) { }
    // Field
    private string name;
    private int age;

    // Constructor that takes no arguments.
    public Person()
    {
        name = "unknown";
        this.age = -1;
    }

    // Constructor that takes one argument.
    public Person(string nm)
    {
        name = nm;
    }

    public Person(string nm, int age)
    {
        name = nm;
        this.age = age;
    }

    // Method
    private void SetName(string newName)
    {
        // comment
        name = newName;

        int x = 99;
        x += this.age;
    }

    public string GetAge() { return this.age; }

    public string Name { get { return this.name; }}
}   